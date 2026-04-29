package main

import (
	"log"
	"net/http"
	"os"

	"ipesign/internal/api"
)

func main() {
	addr := envOrDefault("IPESIGN_ADDR", "")
	if addr == "" {
		if port := os.Getenv("PORT"); port != "" {
			addr = ":" + port
		} else {
			addr = ":8080"
		}
	}
	dataDir := envOrDefault("IPESIGN_DATA_DIR", "./data")
	databaseURL := os.Getenv("DATABASE_URL")
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseJWTSecret := os.Getenv("SUPABASE_JWT_SECRET")
	supabasePublishableKey := envOrDefault("SUPABASE_PUBLISHABLE_KEY", os.Getenv("SUPABASE_ANON_KEY"))
	allowedOrigin := envOrDefault("CORS_ALLOW_ORIGIN", "*")

	server, err := api.NewServer(api.Config{
		DataDir:           dataDir,
		DatabaseURL:       databaseURL,
		MasterKey:         os.Getenv("IPESIGN_MASTER_KEY"),
		SupabaseURL:       supabaseURL,
		SupabaseJWTSecret: supabaseJWTSecret,
		SupabasePublishableKey: supabasePublishableKey,
		AllowedOrigin:     allowedOrigin,
	})
	if err != nil {
		log.Fatalf("failed to create API server: %v", err)
	}

	log.Printf("ipesign api listening on %s", addr)
	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}

func envOrDefault(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}
