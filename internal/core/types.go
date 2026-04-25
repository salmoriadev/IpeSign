package core

import (
	"crypto/ed25519"
	"crypto/x509"
	"sync/atomic"
	"time"

	"ipesign/internal/authority"
	"ipesign/internal/ledger/localchain"
	"ipesign/internal/persist"
)

const MaxPDFSize = 20 << 20
const DefaultPolicyID = "participation-v1"

type Config struct {
	DataDir     string
	DatabaseURL string
	MasterKey   string
}

type Authority interface {
	IssuerID() string
	IssuerName() string
	CertificatePEM() string
	CertificateHash() string
	PublicKeyHash() string
	RootCertificatePEM() string
	PrivateKeyPEM() ([]byte, error)
	RootPrivateKeyPEM() ([]byte, error)
	IssueDocumentCertificate(documentHash, policyID string, identity authority.CertificateIdentity) (*authority.IssuedDocumentCertificate, error)
	VerifyIssuedCertificate(cert *x509.Certificate) error
}

type SignerIdentity struct {
	CommonName         string
	EmailAddress       string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
}

func (s SignerIdentity) toAuthorityIdentity() authority.CertificateIdentity {
	return authority.CertificateIdentity{
		CommonName:         s.CommonName,
		EmailAddress:       s.EmailAddress,
		Organization:       s.Organization,
		OrganizationalUnit: s.OrganizationalUnit,
		Country:            s.Country,
		Province:           s.Province,
		Locality:           s.Locality,
	}
}

type Ledger interface {
	Verify() (*localchain.VerificationReport, error)
	Len() int
	TraverseForward(fn func(*localchain.Node) error) error
	TraverseBackward(fn func(*localchain.Node) error) error
	GetSignatureNodeByRecordID(recordID string) *localchain.Node
	GetCertificateNode(certHash string) *localchain.Node
	VerifyRecord(input localchain.VerifyRecordInput) (*localchain.RecordVerificationResult, error)
	AppendEvent(eventType string, payload any) (*localchain.Node, error)
	Snapshot() []localchain.Block
}

type Service struct {
	store     persist.StateStore
	ledgerKey ed25519.PrivateKey
	authority Authority
	chain     Ledger
	recordSeq atomic.Uint64
}

type Summary struct {
	Status        string `json:"status"`
	IssuerID      string `json:"issuerId"`
	IssuerName    string `json:"issuerName"`
	ChainBlocks   int    `json:"chainBlocks"`
	LastBlockHash string `json:"lastBlockHash,omitempty"`
}

type CAInfo struct {
	IssuerID          string `json:"issuerId"`
	IssuerName        string `json:"issuerName"`
	CACertificate     string `json:"caCertificate"`
	CACertificateHash string `json:"caCertificateHash"`
	CAPublicKeyHash   string `json:"caPublicKeyHash"`
}

type SignResult struct {
	Mode              string `json:"mode"`
	FileName          string `json:"fileName"`
	IssuerID          string `json:"issuerId"`
	DocumentHash      string `json:"documentHash"`
	SignedHashBase64  string `json:"signedHashBase64"`
	SignatureBase64   string `json:"signatureBase64"`
	SignatureHash     string `json:"signatureHash"`
	CertificatePEM    string `json:"certificatePem"`
	CertHash          string `json:"certHash"`
	PublicKeyHash     string `json:"publicKeyHash"`
	PolicyID          string `json:"policyId"`
	SingleUse         bool   `json:"singleUse"`
	RecordID          string `json:"recordId"`
	SignedPDFHash     string `json:"signedPdfHash"`
	EphemeralDisposed bool   `json:"ephemeralDisposed"`
}

type VerifyResult struct {
	Valid                      bool   `json:"valid"`
	DocumentHash               string `json:"documentHash"`
	CertificateTrusted         bool   `json:"certificateTrusted"`
	CertificateDocumentHash    string `json:"certificateDocumentHash"`
	CertificateDocumentMatches bool   `json:"certificateDocumentMatches"`
	PolicyID                   string `json:"policyId"`
	SingleUseInCertificate     bool   `json:"singleUseInCertificate"`
	SignatureValid             bool   `json:"signatureValid"`
	LedgerRecordValid          bool   `json:"ledgerRecordValid"`
	SingleUseConfirmed         bool   `json:"singleUseConfirmed"`
	RecordID                   string `json:"recordId"`
	CertHash                   string `json:"certHash"`
	SignatureHash              string `json:"signatureHash"`
	CertificateRevoked         bool   `json:"certificateRevoked"`
	SignatureRevoked           bool   `json:"signatureRevoked"`
}

type ChainWalkBlock struct {
	Index       uint64    `json:"index"`
	EventType   string    `json:"eventType"`
	BlockHash   string    `json:"blockHash"`
	PrevHash    string    `json:"prevHash"`
	Timestamp   time.Time `json:"timestamp"`
	PayloadHash string    `json:"payloadHash"`
}

type ChainWalkResult struct {
	Direction string           `json:"direction"`
	Blocks    []ChainWalkBlock `json:"blocks"`
}

type RecordResult struct {
	RecordID              string `json:"recordId"`
	CertHash              string `json:"certHash"`
	PublicKeyHash         string `json:"publicKeyHash"`
	IssuerID              string `json:"issuerId"`
	PolicyID              string `json:"policyId"`
	DocumentHash          string `json:"documentHash"`
	SignedPDFHash         string `json:"signedPdfHash"`
	SignatureHash         string `json:"signatureHash"`
	SingleUse             bool   `json:"singleUse"`
	Valid                 bool   `json:"valid"`
	LedgerRecordValid     bool   `json:"ledgerRecordValid"`
	SingleUseConfirmed    bool   `json:"singleUseConfirmed"`
	CertificateRevoked    bool   `json:"certificateRevoked"`
	SignatureRevoked      bool   `json:"signatureRevoked"`
	CertificateValidFrom  string `json:"certificateValidFrom,omitempty"`
	CertificateValidUntil string `json:"certificateValidUntil,omitempty"`
	CertificateCreatedAt  string `json:"certificateCreatedAt,omitempty"`
	SignedAt              string `json:"signedAt,omitempty"`
	Status                string `json:"status,omitempty"`
}
