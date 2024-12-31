package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/joho/godotenv"

	emailVerifier "github.com/AfterShip/email-verifier"
)

// Middleware for token verification
func verifyToken(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		authToken := r.Header.Get("Authorization")

		if authToken == "" {
			http.Error(w, "Authorization token is required", http.StatusUnauthorized)
			return
		}

		expectedToken := os.Getenv("AUTH_TOKEN")
		if expectedToken == "" {
			http.Error(w, "Server misconfiguration: AUTH_TOKEN not set", http.StatusInternalServerError)
			return
		}

		if authToken != expectedToken {
			http.Error(w, "Invalid authorization token", http.StatusForbidden)
			return
		}
		next(w, r, ps)
	}
}

// GetEmailVerification handles email verification requests
func GetEmailVerification(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	verifier := emailVerifier.NewVerifier().EnableSMTPCheck().Proxy(os.Getenv("PROXY_URL"))
	ret, err := verifier.Verify(ps.ByName("email"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ret.Syntax.Valid {
		_, _ = fmt.Fprint(w, "email address syntax is invalid")
		return
	}

	bytes, err := json.Marshal(ret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, _ = fmt.Fprint(w, string(bytes))
}

func main() {
	// Load .env file if it exists
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found. Make sure to set environment variables manually.")
	}

	// Get the proxy URL from the environment variable
	proxyURL := os.Getenv("PROXY_URL")
	if proxyURL == "" {
		log.Fatal("PROXY_URL environment variable not set")
	}

	// Ensure AUTH_TOKEN is set
	if os.Getenv("AUTH_TOKEN") == "" {
		log.Fatal("AUTH_TOKEN environment variable not set")
	}

	router := httprouter.New()

	// Use the middleware for token verification
	router.GET("/v1/:email/verification", verifyToken(GetEmailVerification))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Println("Server is running on port 8080...")
	log.Fatal(server.ListenAndServe())
}