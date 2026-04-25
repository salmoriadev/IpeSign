package core

import "fmt"

func LooksLikePDF(rawPDFBytes []byte) bool {
	return len(rawPDFBytes) >= 5 && string(rawPDFBytes[:5]) == "%PDF-"
}

func ValidatePDFBytes(rawPDFBytes []byte) error {
	switch {
	case len(rawPDFBytes) == 0:
		return fmt.Errorf("pdf is empty")
	case len(rawPDFBytes) > MaxPDFSize:
		return fmt.Errorf("pdf exceeds 20MB limit")
	case !LooksLikePDF(rawPDFBytes):
		return fmt.Errorf("file does not look like a PDF")
	default:
		return nil
	}
}
