package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"ipesign/internal/cryptoutil"
)

var (
	oidDocumentHash = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidPolicyID     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 2}
	oidSingleUse    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 3}
)

type Config struct {
	IssuerID   string
	IssuerName string
	Clock      func() time.Time
}

type Authority struct {
	issuerID      string
	issuerName    string
	clock         func() time.Time
	cert          *x509.Certificate
	certPEM       string
	key           ed25519.PrivateKey
	certHash      string
	publicKeyHash string
}

type IssuedDocumentCertificate struct {
	Certificate    *x509.Certificate
	CertificatePEM string
	CertHash       string
	PublicKeyHash  string
	PrivateKey     ed25519.PrivateKey
	PublicKey      ed25519.PublicKey
}

func New(cfg Config) (*Authority, error) {
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time {
			return time.Now().UTC()
		}
	}

	if cfg.IssuerID == "" {
		cfg.IssuerID = "ipe"
	}

	if cfg.IssuerName == "" {
		cfg.IssuerName = "Ipe"
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate authority key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate authority serial: %w", err)
	}

	now := cfg.Clock()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: cfg.IssuerName + " Root CA", Organization: []string{cfg.IssuerName}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create authority certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, fmt.Errorf("parse authority certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rawCert,
	})

	publicKeyHash, err := cryptoutil.HashPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &Authority{
		issuerID:      cfg.IssuerID,
		issuerName:    cfg.IssuerName,
		clock:         cfg.Clock,
		cert:          cert,
		certPEM:       string(certPEM),
		key:           privateKey,
		certHash:      cryptoutil.SHA256Tagged(rawCert),
		publicKeyHash: publicKeyHash,
	}, nil
}

func Load(cfg Config, certPEM []byte, keyPEM []byte) (*Authority, error) {
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time {
			return time.Now().UTC()
		}
	}

	if cfg.IssuerID == "" {
		cfg.IssuerID = "ipe"
	}

	if cfg.IssuerName == "" {
		cfg.IssuerName = "Ipe"
	}

	key, err := cryptoutil.ParseEd25519PrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse authority certificate: %w", err)
	}

	publicKeyHash, err := cryptoutil.HashPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return &Authority{
		issuerID:      cfg.IssuerID,
		issuerName:    cfg.IssuerName,
		clock:         cfg.Clock,
		cert:          cert,
		certPEM:       string(certPEM),
		key:           key,
		certHash:      cryptoutil.SHA256Tagged(cert.Raw),
		publicKeyHash: publicKeyHash,
	}, nil
}

func (a *Authority) IssuerID() string {
	return a.issuerID
}

func (a *Authority) IssuerName() string {
	return a.issuerName
}

func (a *Authority) CertificatePEM() string {
	return a.certPEM
}

func (a *Authority) CertificateHash() string {
	return a.certHash
}

func (a *Authority) PublicKeyHash() string {
	return a.publicKeyHash
}

func (a *Authority) PrivateKeyPEM() ([]byte, error) {
	return cryptoutil.MarshalEd25519PrivateKeyPEM(a.key)
}

func (a *Authority) IssueDocumentCertificate(documentHash, policyID string) (*IssuedDocumentCertificate, error) {
	if documentHash == "" {
		return nil, fmt.Errorf("document hash is required")
	}

	if policyID == "" {
		policyID = "default"
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	serialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}

	now := a.clock()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Ipe Single-Use Document Certificate", Organization: []string{a.issuerName}},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       buildExtensions(documentHash, policyID),
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, template, a.cert, publicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rawCert,
	})

	publicKeyHash, err := cryptoutil.HashPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &IssuedDocumentCertificate{
		Certificate:    cert,
		CertificatePEM: string(certPEM),
		CertHash:       cryptoutil.SHA256Tagged(rawCert),
		PublicKeyHash:  publicKeyHash,
		PrivateKey:     privateKey,
		PublicKey:      publicKey,
	}, nil
}

func (a *Authority) VerifyIssuedCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is required")
	}

	if err := cert.CheckSignatureFrom(a.cert); err != nil {
		return fmt.Errorf("certificate not issued by authority: %w", err)
	}

	if cert.IsCA {
		return fmt.Errorf("leaf certificate cannot be a CA")
	}

	return nil
}

func ParseCertificatePEM(raw string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}

func ExtractDocumentHash(cert *x509.Certificate) string {
	return extensionValue(cert, oidDocumentHash)
}

func ExtractPolicyID(cert *x509.Certificate) string {
	return extensionValue(cert, oidPolicyID)
}

func ExtractSingleUse(cert *x509.Certificate) bool {
	return extensionValue(cert, oidSingleUse) == "true"
}

func extensionValue(cert *x509.Certificate, oid asn1.ObjectIdentifier) string {
	if cert == nil {
		return ""
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			var value string
			if _, err := asn1.Unmarshal(ext.Value, &value); err == nil {
				return value
			}
		}
	}

	return ""
}

func buildExtensions(documentHash, policyID string) []pkix.Extension {
	return []pkix.Extension{
		mustExtension(oidDocumentHash, documentHash),
		mustExtension(oidPolicyID, policyID),
		mustExtension(oidSingleUse, "true"),
	}
}

func mustExtension(oid asn1.ObjectIdentifier, value string) pkix.Extension {
	raw, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}

	return pkix.Extension{
		Id:    oid,
		Value: raw,
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}

	return serialNumber, nil
}
