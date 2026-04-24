package router

import (
	"net/http"

	"ipesign/apps/api/http/handlers"
	coreapi "ipesign/internal/api"
)

func New(server *coreapi.Server) http.Handler {
	apiHandlers := handlers.New(server)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", apiHandlers.Health)
	mux.HandleFunc("GET /v1/ca", apiHandlers.CA)
	mux.HandleFunc("POST /v1/documents/sign", apiHandlers.Sign)
	mux.HandleFunc("POST /v1/documents/verify", apiHandlers.Verify)
	mux.HandleFunc("GET /v1/records/{recordId}", apiHandlers.Record)
	mux.HandleFunc("GET /v1/chain/walk", apiHandlers.ChainWalk)
	mux.HandleFunc("GET /v1/chain/verify", apiHandlers.ChainVerify)

	mux.HandleFunc("POST /v1/sign", apiHandlers.Sign)
	mux.HandleFunc("POST /v1/verify", apiHandlers.Verify)

	return mux
}
