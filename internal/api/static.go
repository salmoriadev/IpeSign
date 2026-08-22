package api

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const cspNoncePlaceholder = "{{CSP_NONCE}}"

func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.Dir(s.staticDir))
	var indexOnce sync.Once
	var indexHTML []byte
	var indexErr error

	loadIndex := func() {
		indexHTML, indexErr = os.ReadFile(filepath.Join(s.staticDir, "index.html"))
		if indexErr == nil && !bytes.Contains(indexHTML, []byte(cspNoncePlaceholder)) {
			indexErr = fmt.Errorf("index.html is missing the CSP nonce placeholder")
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			indexOnce.Do(loadIndex)
			if indexErr != nil {
				writeError(w, http.StatusInternalServerError, "web interface is unavailable")
				return
			}
			nonce := responseNonce(r.Context())
			body := bytes.ReplaceAll(indexHTML, []byte(cspNoncePlaceholder), []byte(nonce))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			if r.Method == http.MethodGet {
				_, _ = w.Write(body)
			}
			return
		}

		if r.URL.Path != "/ipesign-city-logo.png" && !strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fileServer.ServeHTTP(w, r)
	})
}
