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

func verifyToken(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		log.Println("verifyToken middleware executed")

		authToken := r.Header.Get("Authorization")
		log.Println("Authorization header received:", authToken)

		expectedToken := os.Getenv("AUTH_TOKEN")
		log.Println("Expected token from environment:", expectedToken)

		if authToken == "" {
			log.Println("Missing Authorization header")
			http.Error(w, "Authorization token is required", http.StatusUnauthorized)
			return
		}

		if authToken != expectedToken {
			log.Println("Invalid Authorization token")
			http.Error(w, "Invalid authorization token", http.StatusForbidden)
			return
		}

		log.Println("Authorization successful")
		next(w, r, ps)
	}
}

// GetEmailVerification handles email verification requests
func GetEmailVerification(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fromEmail := os.Getenv("FROM_EMAIL")
	heloName := os.Getenv("HELO_NAME")
	proxyURL := os.Getenv("PROXY_URL")

	if fromEmail == "" || heloName == "" {
		http.Error(w, "FROM_EMAIL and HELO_NAME must be set in environment variables", http.StatusInternalServerError)
		return
	}

	verifier := emailVerifier.NewVerifier().
		EnableSMTPCheck().
		Proxy(proxyURL).
		FromEmail(fromEmail).
		HelloName(heloName)

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

	// Ensure required environment variables are set
	if os.Getenv("AUTH_TOKEN") == "" {
		log.Fatal("AUTH_TOKEN environment variable not set")
	}
	if os.Getenv("FROM_EMAIL") == "" || os.Getenv("HELO_NAME") == "" {
		log.Fatal("FROM_EMAIL and HELO_NAME environment variables must be set")
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