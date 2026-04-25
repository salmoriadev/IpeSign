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
	issuerID          string
	issuerName        string
	clock             func() time.Time
	rootCert          *x509.Certificate
	rootCertPEM       string
	rootKey           ed25519.PrivateKey
	cert              *x509.Certificate
	certPEM           string
	key               ed25519.PrivateKey
	rootCertHash      string
	rootPublicKeyHash string
	certHash          string
	publicKeyHash     string
}

type IssuedDocumentCertificate struct {
	Certificate    *x509.Certificate
	CertificatePEM string
	CertHash       string
	PublicKeyHash  string
	PrivateKey     ed25519.PrivateKey
	PublicKey      ed25519.PublicKey
}

func createCertificateHelper(template, parent *x509.Certificate, pubKey ed25519.PublicKey, privKey ed25519.PrivateKey) (*x509.Certificate, string, string, error) {
	rawCert, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, privKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse certificate: %w", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rawCert,
	}))

	return cert, certPEM, cryptoutil.SHA256Tagged(rawCert), nil
}

func parseCertificateAndHash(pemBytes []byte) (*x509.Certificate, string, string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, "", "", fmt.Errorf("invalid PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse certificate: %w", err)
	}

	publicKeyHash, err := cryptoutil.HashPublicKey(cert.PublicKey)
	if err != nil {
		return nil, "", "", err
	}

	return cert, cryptoutil.SHA256Tagged(cert.Raw), publicKeyHash, nil
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

	rootPublicKey, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate authority key: %w", err)
	}

	rootSerialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate authority serial: %w", err)
	}

	now := cfg.Clock()
	rootTemplate := &x509.Certificate{
		SerialNumber:          rootSerialNumber,
		Subject:               pkix.Name{CommonName: cfg.IssuerName + " Root CA", Organization: []string{cfg.IssuerName}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootCert, rootCertPEM, rootCertHash, err := createCertificateHelper(rootTemplate, rootTemplate, rootPublicKey, rootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}

	rootPublicKeyHash, err := cryptoutil.HashPublicKey(rootPublicKey)
	if err != nil {
		return nil, err
	}

	issuingPublicKey, issuingPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate issuing authority key: %w", err)
	}

	issuingSerialNumber, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate issuing authority serial: %w", err)
	}

	issuingTemplate := &x509.Certificate{
		SerialNumber:          issuingSerialNumber,
		Subject:               pkix.Name{CommonName: cfg.IssuerName + " Issuing CA", Organization: []string{cfg.IssuerName}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	issuingCert, issuingCertPEM, issuingCertHash, err := createCertificateHelper(issuingTemplate, rootCert, issuingPublicKey, rootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create issuing certificate: %w", err)
	}

	issuingPublicKeyHash, err := cryptoutil.HashPublicKey(issuingPublicKey)
	if err != nil {
		return nil, err
	}

	return &Authority{
		issuerID:          cfg.IssuerID,
		issuerName:        cfg.IssuerName,
		clock:             cfg.Clock,
		rootCert:          rootCert,
		rootCertPEM:       rootCertPEM,
		rootKey:           rootPrivateKey,
		cert:              issuingCert,
		certPEM:           issuingCertPEM,
		key:               issuingPrivateKey,
		rootCertHash:      rootCertHash,
		rootPublicKeyHash: rootPublicKeyHash,
		certHash:          issuingCertHash,
		publicKeyHash:     issuingPublicKeyHash,
	}, nil
}

func Load(cfg Config, rootCertPEM []byte, rootKeyPEM []byte, certPEM []byte, keyPEM []byte) (*Authority, error) {
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

	cert, certHash, publicKeyHash, err := parseCertificateAndHash(certPEM)
	if err != nil {
		return nil, fmt.Errorf("load issuing certificate: %w", err)
	}

	var rootCert *x509.Certificate
	var rootKey ed25519.PrivateKey
	var rootCertHash string
	var rootPublicKeyHash string

	if len(rootCertPEM) > 0 {
		rootCert, rootCertHash, rootPublicKeyHash, err = parseCertificateAndHash(rootCertPEM)
		if err != nil {
			return nil, fmt.Errorf("load root certificate: %w", err)
		}
	}

	if len(rootKeyPEM) > 0 {
		rootKey, err = cryptoutil.ParseEd25519PrivateKeyPEM(rootKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse root authority private key: %w", err)
		}
	}

	return &Authority{
		issuerID:          cfg.IssuerID,
		issuerName:        cfg.IssuerName,
		clock:             cfg.Clock,
		rootCert:          rootCert,
		rootCertPEM:       string(rootCertPEM),
		rootKey:           rootKey,
		cert:              cert,
		certPEM:           string(certPEM),
		key:               key,
		rootCertHash:      rootCertHash,
		rootPublicKeyHash: rootPublicKeyHash,
		certHash:          certHash,
		publicKeyHash:     publicKeyHash,
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

func (a *Authority) RootCertificatePEM() string {
	return a.rootCertPEM
}

func (a *Authority) CertificateHash() string {
	return a.certHash
}

func (a *Authority) RootCertificateHash() string {
	return a.rootCertHash
}

func (a *Authority) PublicKeyHash() string {
	return a.publicKeyHash
}

func (a *Authority) RootPublicKeyHash() string {
	return a.rootPublicKeyHash
}

func (a *Authority) PrivateKeyPEM() ([]byte, error) {
	return cryptoutil.MarshalEd25519PrivateKeyPEM(a.key)
}

func (a *Authority) RootPrivateKeyPEM() ([]byte, error) {
	if len(a.rootKey) == 0 {
		return nil, nil
	}

	return cryptoutil.MarshalEd25519PrivateKeyPEM(a.rootKey)
}

type CertificateIdentity struct {
	CommonName         string
	EmailAddress       string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
}

func (a *Authority) IssueDocumentCertificate(documentHash, policyID string, identity CertificateIdentity) (*IssuedDocumentCertificate, error) {
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
	
	subject := pkix.Name{
		Organization: []string{a.issuerName},
	}
	
	if identity.CommonName != "" {
		subject.CommonName = identity.CommonName
	} else {
		subject.CommonName = "Ipe Single-Use Document Certificate"
	}
	
	if identity.Organization != "" {
		subject.Organization = append(subject.Organization, identity.Organization)
	}
	if identity.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{identity.OrganizationalUnit}
	}
	if identity.Country != "" {
		subject.Country = []string{identity.Country}
	}
	if identity.Province != "" {
		subject.Province = []string{identity.Province}
	}
	if identity.Locality != "" {
		subject.Locality = []string{identity.Locality}
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(10 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       buildExtensions(documentHash, policyID),
	}

	if identity.EmailAddress != "" {
		template.EmailAddresses = []string{identity.EmailAddress}
	}

	cert, certPEM, certHash, err := createCertificateHelper(template, a.cert, publicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}

	publicKeyHash, err := cryptoutil.HashPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return &IssuedDocumentCertificate{
		Certificate:    cert,
		CertificatePEM: certPEM,
		CertHash:       certHash,
		PublicKeyHash:  publicKeyHash,
		PrivateKey:     privateKey,
		PublicKey:      publicKey,
	}, nil
}

func (a *Authority) VerifyIssuedCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is required")
	}

	if cert.IsCA {
		return fmt.Errorf("leaf certificate cannot be a CA")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	if a.rootCert != nil {
		roots.AddCert(a.rootCert)
		intermediates.AddCert(a.cert)
	} else {
		roots.AddCert(a.cert)
	}

	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   a.clock(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return fmt.Errorf("certificate not trusted by authority: %w", err)
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
