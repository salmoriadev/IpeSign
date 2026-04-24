package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"ipesign/internal/api"
	"ipesign/internal/ledger/localchain"
)

type bundleFile struct {
	VerifyKeyBase64 string                       `json:"verifyKeyBase64"`
	Blocks          []localchain.Block           `json:"blocks"`
	RecordInput     localchain.VerifyRecordInput `json:"recordInput"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error

	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "demo":
		err = runDemo(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "walk":
		err = runWalk(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "listen address")
	databaseURL := fs.String("database-url", envOrDefault("DATABASE_URL", ""), "PostgreSQL connection string")
	if err := fs.Parse(args); err != nil {
		return err
	}

	server, err := api.NewServer(api.Config{
		DataDir:     "./data",
		DatabaseURL: *databaseURL,
	})
	if err != nil {
		return err
	}

	log.Printf("ipesign server listening on %s", *addr)
	return http.ListenAndServe(*addr, server.Handler())
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	outPath := fs.String("out", "", "output signature sidecar path")
	policyID := fs.String("policy", api.DefaultPolicyID, "policy id")
	dataDir := fs.String("data-dir", "./data", "data directory for CA and blockchain")
	databaseURL := fs.String("database-url", envOrDefault("DATABASE_URL", ""), "PostgreSQL connection string")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: ipesign sign [--out file.ipesign.json] /path/file.pdf")
	}

	pdfPath := fs.Arg(0)
	if *outPath == "" {
		*outPath = defaultSidecarPath(pdfPath)
	}

	pdfBytes, err := os.ReadFile(pdfPath)
	if err != nil {
		return fmt.Errorf("read pdf: %w", err)
	}

	server, err := api.NewServer(api.Config{
		DataDir:     *dataDir,
		DatabaseURL: *databaseURL,
	})
	if err != nil {
		return err
	}

	result, err := server.SignPDF(pdfBytes, filepath.Base(pdfPath), *policyID)
	if err != nil {
		return err
	}

	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signature sidecar: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		return fmt.Errorf("create sidecar directory: %w", err)
	}

	if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
		return fmt.Errorf("write signature sidecar: %w", err)
	}

	fmt.Printf("signed: %s\n", pdfPath)
	fmt.Printf("sidecar: %s\n", *outPath)
	fmt.Printf("document hash: %s\n", result.DocumentHash)
	fmt.Printf("record id: %s\n", result.RecordID)
	fmt.Printf("cert hash: %s\n", result.CertHash)

	return nil
}

func runDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	outPath := fs.String("out", "./data/demo-chain.json", "output bundle path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	verifyKey, signingKey, err := localchain.GenerateSealer()
	if err != nil {
		return fmt.Errorf("generate sealer: %w", err)
	}

	chain, err := localchain.NewChain(localchain.Config{
		Signer:    signingKey,
		VerifyKey: verifyKey,
	})
	if err != nil {
		return fmt.Errorf("create chain: %w", err)
	}

	issuer := localchain.IssuerRegisteredPayload{
		IssuerID: "ipe",
		Name:     "Ipe",
	}
	if _, err := chain.AppendEvent(localchain.EventTypeIssuerRegistered, issuer); err != nil {
		return fmt.Errorf("append issuer: %w", err)
	}

	certificate := localchain.CertificateIssuedPayload{
		CertHash:      "sha256:cert-demo-001",
		PublicKeyHash: "sha256:pub-demo-001",
		IssuerID:      issuer.IssuerID,
		DocumentHash:  "sha256:doc-demo-001",
		PolicyID:      "participation-v1",
		SingleUse:     true,
	}
	if _, err := chain.AppendEvent(localchain.EventTypeCertificateIssued, certificate); err != nil {
		return fmt.Errorf("append certificate: %w", err)
	}

	signature := localchain.SignatureRegisteredPayload{
		RecordID:      "pdfsig-demo-001",
		CertHash:      certificate.CertHash,
		DocumentHash:  certificate.DocumentHash,
		SignedPDFHash: "sha256:signed-demo-001",
		SignatureHash: "sha256:signature-demo-001",
		IssuerID:      certificate.IssuerID,
		PolicyID:      certificate.PolicyID,
		Status:        "VALID",
	}
	if _, err := chain.AppendEvent(localchain.EventTypeSignatureRegistered, signature); err != nil {
		return fmt.Errorf("append signature: %w", err)
	}

	report, err := chain.Verify()
	if err != nil {
		return fmt.Errorf("verify chain after demo generation: %w", err)
	}

	recordResult, err := chain.VerifyRecord(localchain.VerifyRecordInput{
		CertHash:      certificate.CertHash,
		DocumentHash:  certificate.DocumentHash,
		SignedPDFHash: signature.SignedPDFHash,
		SignatureHash: signature.SignatureHash,
	})
	if err != nil {
		return fmt.Errorf("verify record after demo generation: %w", err)
	}

	bundle := bundleFile{
		VerifyKeyBase64: base64.StdEncoding.EncodeToString(verifyKey),
		Blocks:          chain.Snapshot(),
		RecordInput: localchain.VerifyRecordInput{
			CertHash:      certificate.CertHash,
			DocumentHash:  certificate.DocumentHash,
			SignedPDFHash: signature.SignedPDFHash,
			SignatureHash: signature.SignatureHash,
		},
	}

	if err := writeBundle(*outPath, bundle); err != nil {
		return err
	}

	fmt.Printf("demo bundle written to %s\n", *outPath)
	fmt.Printf("blocks verified: %d\n", report.BlocksVerified)
	fmt.Printf("last block hash: %s\n", report.LastBlockHash)
	fmt.Printf("record valid: %t\n", recordResult.Valid)
	fmt.Printf("cert hash: %s\n", certificate.CertHash)
	fmt.Printf("record id: %s\n", signature.RecordID)

	return nil
}

func runVerify(args []string) error {
	if containsBundleFlag(args) {
		return runVerifyBundle(args)
	}

	if hasPositionalPath(args) {
		return runVerifyFile(args)
	}

	return runVerifyBundle(args)
}

func runVerifyFile(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	sidecarPath := fs.String("sidecar", "", "signature sidecar path")
	dataDir := fs.String("data-dir", "./data", "data directory for CA and blockchain")
	databaseURL := fs.String("database-url", envOrDefault("DATABASE_URL", ""), "PostgreSQL connection string")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 1 {
		return fmt.Errorf("usage: ipesign verify [--sidecar file.ipesign.json] /path/file.pdf")
	}

	pdfPath := fs.Arg(0)
	if *sidecarPath == "" {
		*sidecarPath = defaultSidecarPath(pdfPath)
	}

	pdfBytes, err := os.ReadFile(pdfPath)
	if err != nil {
		return fmt.Errorf("read pdf: %w", err)
	}

	rawSidecar, err := os.ReadFile(*sidecarPath)
	if err != nil {
		return fmt.Errorf("read sidecar: %w", err)
	}

	var sidecar api.SignResult
	if err := json.Unmarshal(rawSidecar, &sidecar); err != nil {
		return fmt.Errorf("decode sidecar: %w", err)
	}

	server, err := api.NewServer(api.Config{
		DataDir:     *dataDir,
		DatabaseURL: *databaseURL,
	})
	if err != nil {
		return err
	}

	result, err := server.VerifyPDF(pdfBytes, sidecar.CertificatePEM, sidecar.SignatureBase64)
	if err != nil {
		return err
	}

	rawResult, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("encode verify result: %w", err)
	}

	fmt.Println(string(rawResult))
	return nil
}

func runVerifyBundle(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	bundlePath := fs.String("bundle", "./data/demo-chain.json", "bundle file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	bundle, err := readBundle(*bundlePath)
	if err != nil {
		return err
	}

	verifyKey, err := base64.StdEncoding.DecodeString(bundle.VerifyKeyBase64)
	if err != nil {
		return fmt.Errorf("decode verify key: %w", err)
	}

	chain, err := localchain.OpenChain(localchain.Config{
		VerifyKey: verifyKey,
	}, bundle.Blocks)
	if err != nil {
		return fmt.Errorf("open chain: %w", err)
	}

	report, err := chain.Verify()
	if err != nil {
		return fmt.Errorf("verify chain: %w", err)
	}

	record, err := chain.VerifyRecord(bundle.RecordInput)
	if err != nil {
		return fmt.Errorf("verify record: %w", err)
	}

	fmt.Printf("bundle: %s\n", *bundlePath)
	fmt.Printf("chain valid: %t\n", report.Valid)
	fmt.Printf("blocks verified: %d\n", report.BlocksVerified)
	fmt.Printf("last block hash: %s\n", report.LastBlockHash)
	fmt.Printf("record valid: %t\n", record.Valid)
	fmt.Printf("single use confirmed: %t\n", record.SingleUseConfirmed)
	fmt.Printf("certificate found: %t\n", record.CertificateFound)
	fmt.Printf("signature found: %t\n", record.SignatureFound)
	fmt.Printf("record id: %s\n", record.RecordID)

	return nil
}

func runWalk(args []string) error {
	fs := flag.NewFlagSet("walk", flag.ContinueOnError)
	bundlePath := fs.String("bundle", "./data/demo-chain.json", "bundle file path")
	reverse := fs.Bool("reverse", false, "walk the chain backwards")
	if err := fs.Parse(args); err != nil {
		return err
	}

	bundle, err := readBundle(*bundlePath)
	if err != nil {
		return err
	}

	verifyKey, err := base64.StdEncoding.DecodeString(bundle.VerifyKeyBase64)
	if err != nil {
		return fmt.Errorf("decode verify key: %w", err)
	}

	chain, err := localchain.OpenChain(localchain.Config{
		VerifyKey: verifyKey,
	}, bundle.Blocks)
	if err != nil {
		return fmt.Errorf("open chain: %w", err)
	}

	printNode := func(node *localchain.Node) error {
		fmt.Printf(
			"index=%d event=%s block=%s prev=%s\n",
			node.Block.Index,
			node.Block.EventType,
			shortHash(node.Block.BlockHash),
			shortHash(node.Block.PrevHash),
		)
		return nil
	}

	if *reverse {
		return chain.TraverseBackward(printNode)
	}

	return chain.TraverseForward(printNode)
}

func writeBundle(path string, bundle bundleFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create bundle directory: %w", err)
	}

	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}

	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	return nil
}

func readBundle(path string) (*bundleFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}

	var bundle bundleFile
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}

	if len(bundle.Blocks) == 0 {
		return nil, fmt.Errorf("bundle has no blocks")
	}

	if bundle.VerifyKeyBase64 == "" {
		return nil, fmt.Errorf("bundle has no verify key")
	}

	return &bundle, nil
}

func shortHash(value string) string {
	if value == "" {
		return "<genesis>"
	}

	const prefix = "sha256:"
	value = strings.TrimPrefix(value, prefix)
	if len(value) <= 12 {
		return value
	}

	return value[:12]
}

func usage() {
	fmt.Println("usage:")
	fmt.Println("  ipesign server [--addr :8080] [--database-url $DATABASE_URL]")
	fmt.Println("  ipesign sign   [/path/file.pdf] [--database-url $DATABASE_URL]")
	fmt.Println("  ipesign verify [/path/file.pdf] [--database-url $DATABASE_URL]")
	fmt.Println("  ipesign demo   [--out ./data/demo-chain.json]")
	fmt.Println("  ipesign verify [--bundle ./data/demo-chain.json]")
	fmt.Println("  ipesign walk   [--bundle ./data/demo-chain.json] [--reverse]")
}

func defaultSidecarPath(pdfPath string) string {
	return pdfPath + ".ipesign.json"
}

func hasPositionalPath(args []string) bool {
	for _, arg := range args {
		if arg == "" {
			continue
		}

		if strings.HasPrefix(arg, "-") {
			continue
		}

		return true
	}

	return false
}

func containsBundleFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-bundle" || arg == "--bundle" || strings.HasPrefix(arg, "-bundle=") || strings.HasPrefix(arg, "--bundle=") {
			return true
		}
	}

	return false
}

func envOrDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}
