package core

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ipesign/internal/authority"
	"ipesign/internal/ledger/localchain"
	"ipesign/internal/persist"
)

func defaultAuthorityConfig() authority.Config {
	return authority.Config{
		IssuerID:   "ipe",
		IssuerName: "Ipe",
	}
}

func newServiceInstance(store persist.StateStore, ledgerKey ed25519.PrivateKey, auth Authority, chain Ledger) *Service {
	svc := &Service{
		store:     store,
		ledgerKey: ledgerKey,
		authority: auth,
		chain:     chain,
	}
	svc.recordSeq.Store(nextRecordSequence(chain))
	return svc
}

func bootstrapService(stateStore persist.StateStore) (*Service, error) {
	ledgerVerifyKey, ledgerSigningKey, err := localchain.GenerateSealer()
	if err != nil {
		return nil, fmt.Errorf("generate ledger keys: %w", err)
	}

	ledgerChain, err := localchain.NewChain(localchain.Config{
		Signer:    ledgerSigningKey,
		VerifyKey: ledgerVerifyKey,
	})
	if err != nil {
		return nil, fmt.Errorf("create chain: %w", err)
	}

	documentAuthority, err := authority.New(defaultAuthorityConfig())
	if err != nil {
		return nil, fmt.Errorf("create authority: %w", err)
	}

	issuerRegisteredPayload := localchain.IssuerRegisteredPayload{
		IssuerID:        documentAuthority.IssuerID(),
		Name:            documentAuthority.IssuerName(),
		CAPublicKeyHash: documentAuthority.PublicKeyHash(),
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	if _, err := ledgerChain.AppendEvent(localchain.EventTypeIssuerRegistered, issuerRegisteredPayload); err != nil {
		return nil, fmt.Errorf("register issuer: %w", err)
	}

	initializedService := newServiceInstance(stateStore, ledgerSigningKey, documentAuthority, ledgerChain)

	if err := initializedService.save(); err != nil {
		return nil, err
	}

	return initializedService, nil
}

func loadService(stateStore persist.StateStore) (*Service, error) {
	persistedState, err := stateStore.Load()
	if err != nil {
		return nil, err
	}

	documentAuthority, err := authority.Load(
		defaultAuthorityConfig(),
		persistedState.RootCACertPEM,
		persistedState.RootCAKeyPEM,
		persistedState.CACertPEM,
		persistedState.CAKeyPEM,
	)
	if err != nil {
		return nil, fmt.Errorf("load authority: %w", err)
	}

	ledgerChain, err := localchain.OpenChain(localchain.Config{
		Signer: persistedState.LedgerKey,
	}, persistedState.Blocks)
	if err != nil {
		return nil, fmt.Errorf("load chain: %w", err)
	}

	loadedService := newServiceInstance(stateStore, persistedState.LedgerKey, documentAuthority, ledgerChain)
	return loadedService, nil
}

func (service *Service) save() error {
	issuingPrivateKeyPEM, err := service.authority.PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("encode authority private key: %w", err)
	}

	rootPrivateKeyPEM, err := service.authority.RootPrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("encode root authority private key: %w", err)
	}

	persistedState := &persist.State{
		RootCACertPEM: []byte(service.authority.RootCertificatePEM()),
		RootCAKeyPEM:  rootPrivateKeyPEM,
		CACertPEM:     []byte(service.authority.CertificatePEM()),
		CAKeyPEM:      issuingPrivateKeyPEM,
		LedgerKey:     service.ledgerKey,
		Blocks:        service.chain.Snapshot(),
	}

	return service.store.Save(persistedState)
}

func nextRecordSequence(ledgerChain Ledger) uint64 {
	var highestRecordSequence uint64

	_ = ledgerChain.TraverseForward(func(node *localchain.Node) error {
		if node.Block.EventType != localchain.EventTypeSignatureRegistered {
			return nil
		}

		signaturePayload, err := decodeLedgerPayload[localchain.SignatureRegisteredPayload](node.Block.Payload)
		if err != nil {
			return nil
		}

		currentRecordSequence, err := parseRecordSequence(signaturePayload.RecordID)
		if err == nil && currentRecordSequence > highestRecordSequence {
			highestRecordSequence = currentRecordSequence
		}

		return nil
	})

	return highestRecordSequence
}

func parseRecordSequence(recordID string) (uint64, error) {
	recordSuffix := strings.TrimPrefix(recordID, "pdfsig-")
	return strconv.ParseUint(recordSuffix, 10, 64)
}
