package localchain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	EventTypeGenesis             = "GENESIS"
	EventTypeIssuerRegistered    = "ISSUER_REGISTERED"
	EventTypeCertificateIssued   = "CERTIFICATE_ISSUED"
	EventTypeSignatureRegistered = "SIGNATURE_REGISTERED"
	EventTypeCertificateRevoked  = "CERTIFICATE_REVOKED"
	EventTypeSignatureRevoked    = "SIGNATURE_REVOKED"
)

var (
	ErrMissingSigningKey        = errors.New("missing ledger signing key")
	ErrMissingVerifyKey         = errors.New("missing ledger verification key")
	ErrChainReadOnly            = errors.New("chain is read-only")
	ErrGenesisAlreadyExists     = errors.New("genesis block already exists")
	ErrUnknownEventType         = errors.New("unknown event type")
	ErrIssuerAlreadyExists      = errors.New("issuer already exists")
	ErrIssuerNotFound           = errors.New("issuer not found")
	ErrCertificateAlreadyExists = errors.New("certificate already exists")
	ErrCertificateNotFound      = errors.New("certificate not found")
	ErrCertificateAlreadyUsed   = errors.New("certificate already used")
	ErrCertificateRevoked       = errors.New("certificate is revoked")
	ErrSignatureAlreadyExists   = errors.New("signature record already exists")
	ErrSignatureNotFound        = errors.New("signature record not found")
	ErrSignatureRevoked         = errors.New("signature is revoked")
	ErrInvalidPayload           = errors.New("invalid event payload")
	ErrVerificationFailed       = errors.New("chain verification failed")
)

type Config struct {
	Signer    ed25519.PrivateKey
	VerifyKey ed25519.PublicKey
	Clock     func() time.Time
}

type Block struct {
	Index           uint64          `json:"index"`
	PrevHash        string          `json:"prevHash"`
	BlockHash       string          `json:"blockHash"`
	Timestamp       time.Time       `json:"timestamp"`
	EventType       string          `json:"eventType"`
	Payload         json.RawMessage `json:"payload"`
	PayloadHash     string          `json:"payloadHash"`
	LedgerSignature string          `json:"ledgerSignature"`
}

type Node struct {
	Block Block
	prev  *Node
	next  *Node
}

func (n *Node) Prev() *Node {
	if n == nil {
		return nil
	}

	return n.prev
}

func (n *Node) Next() *Node {
	if n == nil {
		return nil
	}

	return n.next
}

type IssuerRegisteredPayload struct {
	IssuerID        string `json:"issuerId"`
	Name            string `json:"name"`
	CAPublicKeyHash string `json:"caPublicKeyHash,omitempty"`
	CreatedAt       string `json:"createdAt,omitempty"`
}

type CertificateIssuedPayload struct {
	CertHash      string `json:"certHash"`
	PublicKeyHash string `json:"publicKeyHash"`
	IssuerID      string `json:"issuerId"`
	DocumentHash  string `json:"documentHash"`
	PolicyID      string `json:"policyId"`
	SingleUse     bool   `json:"singleUse"`
	ValidFrom     string `json:"validFrom,omitempty"`
	ValidUntil    string `json:"validUntil,omitempty"`
	CreatedAt     string `json:"createdAt,omitempty"`
}

type SignatureRegisteredPayload struct {
	RecordID      string `json:"recordId"`
	CertHash      string `json:"certHash"`
	DocumentHash  string `json:"documentHash"`
	SignedPDFHash string `json:"signedPdfHash"`
	SignatureHash string `json:"signatureHash"`
	IssuerID      string `json:"issuerId"`
	PolicyID      string `json:"policyId"`
	SignedAt      string `json:"signedAt,omitempty"`
	Status        string `json:"status,omitempty"`
}

type CertificateRevokedPayload struct {
	CertHash  string `json:"certHash"`
	Reason    string `json:"reason"`
	RevokedAt string `json:"revokedAt,omitempty"`
}

type SignatureRevokedPayload struct {
	RecordID  string `json:"recordId"`
	CertHash  string `json:"certHash"`
	Reason    string `json:"reason"`
	RevokedAt string `json:"revokedAt,omitempty"`
}

type VerificationReport struct {
	Valid                bool   `json:"valid"`
	BlocksVerified       int    `json:"blocksVerified"`
	LastBlockHash        string `json:"lastBlockHash"`
	IssuersRegistered    int    `json:"issuersRegistered"`
	CertificatesIssued   int    `json:"certificatesIssued"`
	SignaturesRegistered int    `json:"signaturesRegistered"`
	RevokedCertificates  int    `json:"revokedCertificates"`
	RevokedSignatures    int    `json:"revokedSignatures"`
}

type VerifyRecordInput struct {
	CertHash      string
	DocumentHash  string
	SignedPDFHash string
	SignatureHash string
}

type RecordVerificationResult struct {
	Valid               bool   `json:"valid"`
	ChainValid          bool   `json:"chainValid"`
	CertificateFound    bool   `json:"certificateFound"`
	SignatureFound      bool   `json:"signatureFound"`
	SingleUseConfirmed  bool   `json:"singleUseConfirmed"`
	DocumentHashMatches bool   `json:"documentHashMatches"`
	SignedPDFHashOK     bool   `json:"signedPdfHashMatches"`
	SignatureHashOK     bool   `json:"signatureHashMatches"`
	CertificateRevoked  bool   `json:"certificateRevoked"`
	SignatureRevoked    bool   `json:"signatureRevoked"`
	RecordID            string `json:"recordId,omitempty"`
	BlocksVerified      int    `json:"blocksVerified"`
	LastBlockHash       string `json:"lastBlockHash"`
}

type Chain struct {
	mu sync.RWMutex

	head   *Node
	tail   *Node
	length uint64

	signer    ed25519.PrivateKey
	verifyKey ed25519.PublicKey
	clock     func() time.Time

	issuers               map[string]*Node
	certificates          map[string]*Node
	signaturesByCertHash  map[string]*Node
	signaturesByRecordID  map[string]*Node
	revokedCertificates   map[string]*Node
	revokedSignaturesByID map[string]*Node
	blocksByHash          map[string]*Node
}

type ledgerState struct {
	issuers              map[string]IssuerRegisteredPayload
	certificates         map[string]certificateState
	signaturesByCertHash map[string]signatureState
	signaturesByRecordID map[string]signatureState
	usageCountByCertHash map[string]int
	revokedCertificates  int
	revokedSignatures    int
}

type certificateState struct {
	Payload CertificateIssuedPayload
	Revoked bool
}

type signatureState struct {
	Payload SignatureRegisteredPayload
	Revoked bool
}

type blockHashInput struct {
	Index       uint64 `json:"index"`
	PrevHash    string `json:"prevHash"`
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"eventType"`
	PayloadHash string `json:"payloadHash"`
}

func GenerateSealer() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func NewChain(cfg Config) (*Chain, error) {
	cfg, err := normalizeConfig(cfg, true)
	if err != nil {
		return nil, err
	}

	chain := newEmptyChain(cfg)
	if _, err := chain.appendEventLocked(EventTypeGenesis, map[string]any{
		"network": "ipesign-localchain",
		"version": 1,
	}); err != nil {
		return nil, err
	}

	return chain, nil
}

func OpenChain(cfg Config, blocks []Block) (*Chain, error) {
	if len(blocks) == 0 {
		return NewChain(cfg)
	}

	cfg, err := normalizeConfig(cfg, false)
	if err != nil {
		return nil, err
	}

	chain := newEmptyChain(cfg)
	for i := range blocks {
		block := cloneBlock(blocks[i])
		node := &Node{
			Block: block,
			prev:  chain.tail,
		}

		if chain.tail != nil {
			chain.tail.next = node
		} else {
			chain.head = node
		}

		chain.tail = node
		chain.length++
	}

	if _, _, err := chain.verifyLocked(); err != nil {
		return nil, err
	}

	if err := chain.rebuildIndexesLocked(); err != nil {
		return nil, err
	}

	return chain, nil
}

func (c *Chain) AppendEvent(eventType string, payload any) (*Node, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.appendEventLocked(eventType, payload)
}

func (c *Chain) Snapshot() []Block {
	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make([]Block, 0, c.length)
	for node := c.head; node != nil; node = node.next {
		out = append(out, cloneBlock(node.Block))
	}

	return out
}

func (c *Chain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return int(c.length)
}

func (c *Chain) Head() *Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.head
}

func (c *Chain) Tail() *Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.tail
}

func (c *Chain) GetCertificateNode(certHash string) *Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.certificates[certHash]
}

func (c *Chain) GetSignatureNode(certHash string) *Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.signaturesByCertHash[certHash]
}

func (c *Chain) TraverseForward(fn func(*Node) error) error {
	c.mu.RLock()
	nodes := make([]*Node, 0, c.length)
	for node := c.head; node != nil; node = node.next {
		nodes = append(nodes, node)
	}
	c.mu.RUnlock()

	for _, node := range nodes {
		if err := fn(node); err != nil {
			return err
		}
	}

	return nil
}

func (c *Chain) TraverseBackward(fn func(*Node) error) error {
	c.mu.RLock()
	nodes := make([]*Node, 0, c.length)
	for node := c.tail; node != nil; node = node.prev {
		nodes = append(nodes, node)
	}
	c.mu.RUnlock()

	for _, node := range nodes {
		if err := fn(node); err != nil {
			return err
		}
	}

	return nil
}

func (c *Chain) Verify() (*VerificationReport, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	report, _, err := c.verifyLocked()
	if err != nil {
		return nil, err
	}

	return report, nil
}

func (c *Chain) VerifyRecord(input VerifyRecordInput) (*RecordVerificationResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	report, state, err := c.verifyLocked()
	if err != nil {
		return nil, err
	}

	result := &RecordVerificationResult{
		ChainValid:          report.Valid,
		BlocksVerified:      report.BlocksVerified,
		LastBlockHash:       report.LastBlockHash,
		DocumentHashMatches: true,
		SignedPDFHashOK:     true,
		SignatureHashOK:     true,
	}

	certState, certFound := state.certificates[input.CertHash]
	if !certFound {
		return result, nil
	}

	result.CertificateFound = true
	result.CertificateRevoked = certState.Revoked

	sigState, sigFound := state.signaturesByCertHash[input.CertHash]
	if !sigFound {
		return result, nil
	}

	result.SignatureFound = true
	result.SignatureRevoked = sigState.Revoked
	result.RecordID = sigState.Payload.RecordID
	result.SingleUseConfirmed = state.usageCountByCertHash[input.CertHash] == 1

	if input.DocumentHash != "" {
		result.DocumentHashMatches = certState.Payload.DocumentHash == input.DocumentHash &&
			sigState.Payload.DocumentHash == input.DocumentHash
	}

	if input.SignedPDFHash != "" {
		result.SignedPDFHashOK = sigState.Payload.SignedPDFHash == input.SignedPDFHash
	}

	if input.SignatureHash != "" {
		result.SignatureHashOK = sigState.Payload.SignatureHash == input.SignatureHash
	}

	result.Valid = result.ChainValid &&
		result.CertificateFound &&
		result.SignatureFound &&
		result.SingleUseConfirmed &&
		result.DocumentHashMatches &&
		result.SignedPDFHashOK &&
		result.SignatureHashOK &&
		!result.CertificateRevoked &&
		!result.SignatureRevoked

	return result, nil
}

func (c *Chain) appendEventLocked(eventType string, payload any) (*Node, error) {
	if len(c.signer) == 0 {
		return nil, ErrChainReadOnly
	}

	raw, err := marshalPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}

	if err := c.validateTransitionLocked(eventType, raw); err != nil {
		return nil, err
	}

	block := Block{
		Index:       c.length,
		Timestamp:   c.clock().UTC(),
		EventType:   eventType,
		Payload:     raw,
		PayloadHash: hashPayload(raw),
	}

	if c.tail != nil {
		block.PrevHash = c.tail.Block.BlockHash
	}

	block.BlockHash = computeBlockHash(block)
	block.LedgerSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(c.signer, []byte(block.BlockHash)))

	node := &Node{
		Block: block,
		prev:  c.tail,
	}

	if c.tail != nil {
		c.tail.next = node
	} else {
		c.head = node
	}

	c.tail = node
	c.length++

	if err := c.indexNodeLocked(node); err != nil {
		if node.prev != nil {
			node.prev.next = nil
		} else {
			c.head = nil
		}

		c.tail = node.prev
		c.length--
		return nil, err
	}

	return node, nil
}

func (c *Chain) verifyLocked() (*VerificationReport, *ledgerState, error) {
	if c.head == nil || c.tail == nil || c.length == 0 {
		return nil, nil, fmt.Errorf("%w: empty chain", ErrVerificationFailed)
	}

	state := newLedgerState()
	report := &VerificationReport{
		Valid: true,
	}

	var previous *Node
	for current := c.head; current != nil; current = current.next {
		block := current.Block

		if previous == nil {
			if current.prev != nil {
				return nil, nil, fmt.Errorf("%w: genesis prev pointer must be nil", ErrVerificationFailed)
			}

			if block.Index != 0 {
				return nil, nil, fmt.Errorf("%w: genesis index must be zero", ErrVerificationFailed)
			}

			if block.PrevHash != "" {
				return nil, nil, fmt.Errorf("%w: genesis prev hash must be empty", ErrVerificationFailed)
			}
		} else {
			if current.prev != previous || previous.next != current {
				return nil, nil, fmt.Errorf("%w: linked list pointers are inconsistent at block %d", ErrVerificationFailed, block.Index)
			}

			if block.Index != previous.Block.Index+1 {
				return nil, nil, fmt.Errorf("%w: invalid index progression at block %d", ErrVerificationFailed, block.Index)
			}

			if block.PrevHash != previous.Block.BlockHash {
				return nil, nil, fmt.Errorf("%w: prev hash mismatch at block %d", ErrVerificationFailed, block.Index)
			}
		}

		if actual := hashPayload(block.Payload); actual != block.PayloadHash {
			return nil, nil, fmt.Errorf("%w: payload hash mismatch at block %d", ErrVerificationFailed, block.Index)
		}

		if actual := computeBlockHash(block); actual != block.BlockHash {
			return nil, nil, fmt.Errorf("%w: block hash mismatch at block %d", ErrVerificationFailed, block.Index)
		}

		signature, err := base64.StdEncoding.DecodeString(block.LedgerSignature)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid block signature encoding at block %d", ErrVerificationFailed, block.Index)
		}

		if !ed25519.Verify(c.verifyKey, []byte(block.BlockHash), signature) {
			return nil, nil, fmt.Errorf("%w: invalid block signature at block %d", ErrVerificationFailed, block.Index)
		}

		if err := applyBlockToState(state, block); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
		}

		report.BlocksVerified++
		previous = current
	}

	if previous != c.tail {
		return nil, nil, fmt.Errorf("%w: tail pointer is inconsistent", ErrVerificationFailed)
	}

	report.LastBlockHash = c.tail.Block.BlockHash
	report.IssuersRegistered = len(state.issuers)
	report.CertificatesIssued = len(state.certificates)
	report.SignaturesRegistered = len(state.signaturesByRecordID)
	report.RevokedCertificates = state.revokedCertificates
	report.RevokedSignatures = state.revokedSignatures

	return report, state, nil
}

func (c *Chain) validateTransitionLocked(eventType string, raw json.RawMessage) error {
	switch eventType {
	case EventTypeGenesis:
		if c.length != 0 {
			return ErrGenesisAlreadyExists
		}
	case EventTypeIssuerRegistered:
		payload, err := decodePayload[IssuerRegisteredPayload](raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}

		if payload.IssuerID == "" || payload.Name == "" {
			return fmt.Errorf("%w: issuerId and name are required", ErrInvalidPayload)
		}

		if _, exists := c.issuers[payload.IssuerID]; exists {
			return ErrIssuerAlreadyExists
		}
	case EventTypeCertificateIssued:
		payload, err := decodePayload[CertificateIssuedPayload](raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}

		if err := validateCertificatePayload(payload); err != nil {
			return err
		}

		if _, exists := c.issuers[payload.IssuerID]; !exists {
			return ErrIssuerNotFound
		}

		if _, exists := c.certificates[payload.CertHash]; exists {
			return ErrCertificateAlreadyExists
		}
	case EventTypeSignatureRegistered:
		payload, err := decodePayload[SignatureRegisteredPayload](raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}

		if err := validateSignaturePayload(payload); err != nil {
			return err
		}

		certNode, certExists := c.certificates[payload.CertHash]
		if !certExists {
			return ErrCertificateNotFound
		}

		if _, revoked := c.revokedCertificates[payload.CertHash]; revoked {
			return ErrCertificateRevoked
		}

		if _, exists := c.signaturesByRecordID[payload.RecordID]; exists {
			return ErrSignatureAlreadyExists
		}

		certPayload, err := decodePayload[CertificateIssuedPayload](certNode.Block.Payload)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}

		if certPayload.SingleUse {
			if _, exists := c.signaturesByCertHash[payload.CertHash]; exists {
				return ErrCertificateAlreadyUsed
			}
		}

		if certPayload.DocumentHash != payload.DocumentHash {
			return fmt.Errorf("%w: document hash mismatch with certificate", ErrInvalidPayload)
		}

		if certPayload.IssuerID != payload.IssuerID {
			return fmt.Errorf("%w: issuer mismatch with certificate", ErrInvalidPayload)
		}

		if certPayload.PolicyID != payload.PolicyID {
			return fmt.Errorf("%w: policy mismatch with certificate", ErrInvalidPayload)
		}
	case EventTypeCertificateRevoked:
		payload, err := decodePayload[CertificateRevokedPayload](raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}

		if payload.CertHash == "" || payload.Reason == "" {
			return fmt.Errorf("%w: certHash and reason are required", ErrInvalidPayload)
		}

		if _, exists := c.certificates[payload.CertHash]; !exists {
			return ErrCertificateNotFound
		}

		if _, exists := c.revokedCertificates[payload.CertHash]; exists {
			return ErrCertificateRevoked
		}
	case EventTypeSignatureRevoked:
		payload, err := decodePayload[SignatureRevokedPayload](raw)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}

		if payload.RecordID == "" || payload.CertHash == "" || payload.Reason == "" {
			return fmt.Errorf("%w: recordId, certHash and reason are required", ErrInvalidPayload)
		}

		signatureNode, exists := c.signaturesByRecordID[payload.RecordID]
		if !exists {
			return ErrSignatureNotFound
		}

		sigPayload, err := decodePayload[SignatureRegisteredPayload](signatureNode.Block.Payload)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
		}

		if sigPayload.CertHash != payload.CertHash {
			return fmt.Errorf("%w: certHash mismatch with signature", ErrInvalidPayload)
		}

		if _, exists := c.revokedSignaturesByID[payload.RecordID]; exists {
			return ErrSignatureRevoked
		}
	default:
		return ErrUnknownEventType
	}

	return nil
}

func (c *Chain) indexNodeLocked(node *Node) error {
	c.blocksByHash[node.Block.BlockHash] = node

	switch node.Block.EventType {
	case EventTypeGenesis:
		return nil
	case EventTypeIssuerRegistered:
		payload, err := decodePayload[IssuerRegisteredPayload](node.Block.Payload)
		if err != nil {
			return err
		}

		c.issuers[payload.IssuerID] = node
	case EventTypeCertificateIssued:
		payload, err := decodePayload[CertificateIssuedPayload](node.Block.Payload)
		if err != nil {
			return err
		}

		c.certificates[payload.CertHash] = node
	case EventTypeSignatureRegistered:
		payload, err := decodePayload[SignatureRegisteredPayload](node.Block.Payload)
		if err != nil {
			return err
		}

		c.signaturesByCertHash[payload.CertHash] = node
		c.signaturesByRecordID[payload.RecordID] = node
	case EventTypeCertificateRevoked:
		payload, err := decodePayload[CertificateRevokedPayload](node.Block.Payload)
		if err != nil {
			return err
		}

		c.revokedCertificates[payload.CertHash] = node
	case EventTypeSignatureRevoked:
		payload, err := decodePayload[SignatureRevokedPayload](node.Block.Payload)
		if err != nil {
			return err
		}

		c.revokedSignaturesByID[payload.RecordID] = node
	default:
		return ErrUnknownEventType
	}

	return nil
}

func (c *Chain) rebuildIndexesLocked() error {
	c.issuers = map[string]*Node{}
	c.certificates = map[string]*Node{}
	c.signaturesByCertHash = map[string]*Node{}
	c.signaturesByRecordID = map[string]*Node{}
	c.revokedCertificates = map[string]*Node{}
	c.revokedSignaturesByID = map[string]*Node{}
	c.blocksByHash = map[string]*Node{}

	for node := c.head; node != nil; node = node.next {
		if err := c.indexNodeLocked(node); err != nil {
			return err
		}
	}

	return nil
}

func applyBlockToState(state *ledgerState, block Block) error {
	switch block.EventType {
	case EventTypeGenesis:
		return nil
	case EventTypeIssuerRegistered:
		payload, err := decodePayload[IssuerRegisteredPayload](block.Payload)
		if err != nil {
			return err
		}

		if payload.IssuerID == "" || payload.Name == "" {
			return fmt.Errorf("issuerId and name are required")
		}

		if _, exists := state.issuers[payload.IssuerID]; exists {
			return ErrIssuerAlreadyExists
		}

		state.issuers[payload.IssuerID] = payload
	case EventTypeCertificateIssued:
		payload, err := decodePayload[CertificateIssuedPayload](block.Payload)
		if err != nil {
			return err
		}

		if err := validateCertificatePayload(payload); err != nil {
			return err
		}

		if _, exists := state.issuers[payload.IssuerID]; !exists {
			return ErrIssuerNotFound
		}

		if _, exists := state.certificates[payload.CertHash]; exists {
			return ErrCertificateAlreadyExists
		}

		state.certificates[payload.CertHash] = certificateState{Payload: payload}
	case EventTypeSignatureRegistered:
		payload, err := decodePayload[SignatureRegisteredPayload](block.Payload)
		if err != nil {
			return err
		}

		if err := validateSignaturePayload(payload); err != nil {
			return err
		}

		certState, exists := state.certificates[payload.CertHash]
		if !exists {
			return ErrCertificateNotFound
		}

		if certState.Revoked {
			return ErrCertificateRevoked
		}

		if _, exists := state.signaturesByRecordID[payload.RecordID]; exists {
			return ErrSignatureAlreadyExists
		}

		if certState.Payload.SingleUse && state.usageCountByCertHash[payload.CertHash] > 0 {
			return ErrCertificateAlreadyUsed
		}

		if certState.Payload.DocumentHash != payload.DocumentHash {
			return fmt.Errorf("%w: document hash mismatch with certificate", ErrInvalidPayload)
		}

		if certState.Payload.IssuerID != payload.IssuerID {
			return fmt.Errorf("%w: issuer mismatch with certificate", ErrInvalidPayload)
		}

		if certState.Payload.PolicyID != payload.PolicyID {
			return fmt.Errorf("%w: policy mismatch with certificate", ErrInvalidPayload)
		}

		state.signaturesByCertHash[payload.CertHash] = signatureState{Payload: payload}
		state.signaturesByRecordID[payload.RecordID] = signatureState{Payload: payload}
		state.usageCountByCertHash[payload.CertHash]++
	case EventTypeCertificateRevoked:
		payload, err := decodePayload[CertificateRevokedPayload](block.Payload)
		if err != nil {
			return err
		}

		if payload.CertHash == "" || payload.Reason == "" {
			return fmt.Errorf("certHash and reason are required")
		}

		certState, exists := state.certificates[payload.CertHash]
		if !exists {
			return ErrCertificateNotFound
		}

		if certState.Revoked {
			return ErrCertificateRevoked
		}

		certState.Revoked = true
		state.certificates[payload.CertHash] = certState
		state.revokedCertificates++
	case EventTypeSignatureRevoked:
		payload, err := decodePayload[SignatureRevokedPayload](block.Payload)
		if err != nil {
			return err
		}

		if payload.RecordID == "" || payload.CertHash == "" || payload.Reason == "" {
			return fmt.Errorf("recordId, certHash and reason are required")
		}

		sigState, exists := state.signaturesByRecordID[payload.RecordID]
		if !exists {
			return ErrSignatureNotFound
		}

		if sigState.Payload.CertHash != payload.CertHash {
			return fmt.Errorf("%w: certHash mismatch with signature", ErrInvalidPayload)
		}

		if sigState.Revoked {
			return ErrSignatureRevoked
		}

		sigState.Revoked = true
		state.signaturesByRecordID[payload.RecordID] = sigState

		byCert := state.signaturesByCertHash[payload.CertHash]
		byCert.Revoked = true
		state.signaturesByCertHash[payload.CertHash] = byCert
		state.revokedSignatures++
	default:
		return ErrUnknownEventType
	}

	return nil
}

func computeBlockHash(block Block) string {
	input := blockHashInput{
		Index:       block.Index,
		PrevHash:    block.PrevHash,
		Timestamp:   block.Timestamp.UTC().Format(time.RFC3339Nano),
		EventType:   block.EventType,
		PayloadHash: block.PayloadHash,
	}

	raw, _ := json.Marshal(input)
	return hashBytes(raw)
}

func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashPayload(raw []byte) string {
	normalized := append([]byte(nil), raw...)
	var compacted []byte
	var buffer bytes.Buffer

	if err := json.Compact(&buffer, normalized); err == nil {
		compacted = buffer.Bytes()
	} else {
		compacted = normalized
	}

	return hashBytes(compacted)
}

func marshalPayload(payload any) (json.RawMessage, error) {
	if raw, ok := payload.(json.RawMessage); ok {
		return append(json.RawMessage(nil), raw...), nil
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return encoded, nil
}

func decodePayload[T any](raw json.RawMessage) (T, error) {
	var out T
	err := json.Unmarshal(raw, &out)
	return out, err
}

func validateCertificatePayload(payload CertificateIssuedPayload) error {
	if payload.CertHash == "" ||
		payload.PublicKeyHash == "" ||
		payload.IssuerID == "" ||
		payload.DocumentHash == "" ||
		payload.PolicyID == "" {
		return fmt.Errorf("%w: certHash, publicKeyHash, issuerId, documentHash and policyId are required", ErrInvalidPayload)
	}

	return nil
}

func validateSignaturePayload(payload SignatureRegisteredPayload) error {
	if payload.RecordID == "" ||
		payload.CertHash == "" ||
		payload.DocumentHash == "" ||
		payload.SignedPDFHash == "" ||
		payload.SignatureHash == "" ||
		payload.IssuerID == "" ||
		payload.PolicyID == "" {
		return fmt.Errorf("%w: recordId, certHash, documentHash, signedPdfHash, signatureHash, issuerId and policyId are required", ErrInvalidPayload)
	}

	return nil
}

func normalizeConfig(cfg Config, requireSigner bool) (Config, error) {
	if cfg.Clock == nil {
		cfg.Clock = func() time.Time {
			return time.Now().UTC()
		}
	}

	if len(cfg.Signer) > 0 && len(cfg.Signer) != ed25519.PrivateKeySize {
		return Config{}, ErrMissingSigningKey
	}

	if len(cfg.VerifyKey) > 0 && len(cfg.VerifyKey) != ed25519.PublicKeySize {
		return Config{}, ErrMissingVerifyKey
	}

	if requireSigner && len(cfg.Signer) == 0 {
		return Config{}, ErrMissingSigningKey
	}

	if len(cfg.VerifyKey) == 0 {
		if len(cfg.Signer) == 0 {
			return Config{}, ErrMissingVerifyKey
		}

		publicKey, ok := cfg.Signer.Public().(ed25519.PublicKey)
		if !ok {
			return Config{}, ErrMissingVerifyKey
		}

		cfg.VerifyKey = append(ed25519.PublicKey(nil), publicKey...)
	} else {
		cfg.VerifyKey = append(ed25519.PublicKey(nil), cfg.VerifyKey...)
	}

	if len(cfg.Signer) > 0 {
		cfg.Signer = append(ed25519.PrivateKey(nil), cfg.Signer...)
	}

	return cfg, nil
}

func newEmptyChain(cfg Config) *Chain {
	return &Chain{
		signer:                cfg.Signer,
		verifyKey:             cfg.VerifyKey,
		clock:                 cfg.Clock,
		issuers:               map[string]*Node{},
		certificates:          map[string]*Node{},
		signaturesByCertHash:  map[string]*Node{},
		signaturesByRecordID:  map[string]*Node{},
		revokedCertificates:   map[string]*Node{},
		revokedSignaturesByID: map[string]*Node{},
		blocksByHash:          map[string]*Node{},
	}
}

func newLedgerState() *ledgerState {
	return &ledgerState{
		issuers:              map[string]IssuerRegisteredPayload{},
		certificates:         map[string]certificateState{},
		signaturesByCertHash: map[string]signatureState{},
		signaturesByRecordID: map[string]signatureState{},
		usageCountByCertHash: map[string]int{},
	}
}

func cloneBlock(block Block) Block {
	out := block
	out.Payload = append(json.RawMessage(nil), block.Payload...)
	return out
}
