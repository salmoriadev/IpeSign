package main

import (
	"log"
	"net/http"
	"os"

	httprouter "ipesign/apps/api/http/router"
	"ipesign/internal/api"
)

func main() {
	addr := envOrDefault("IPESIGN_ADDR", ":8080")
	dataDir := envOrDefault("IPESIGN_DATA_DIR", "./data")
	databaseURL := os.Getenv("DATABASE_URL")

	server, err := api.NewServer(api.Config{
		DataDir:     dataDir,
		DatabaseURL: databaseURL,
	})
	if err != nil {
		log.Fatalf("failed to create API server: %v", err)
	}

	log.Printf("ipesign api listening on %s", addr)
	if err := http.ListenAndServe(addr, httprouter.New(server)); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}

func envOrDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}
