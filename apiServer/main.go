package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"

	emailVerifier "github.com/AfterShip/email-verifier"
)

var MAX_EMAILS = 15

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
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ret.Syntax.Valid {
		_, _ = fmt.Fprint(w, "email address syntax is invalid")
		return
	}

	bytes, err := json.Marshal(ret)
	if err != nil {
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_, _ = fmt.Fprint(w, string(bytes))
}

type BulkVerificationRequest struct {
	Emails []string `json:"emails"`
}

type BulkVerificationResult struct {
	Email  string                `json:"email"`
	Result *emailVerifier.Result `json:"result,omitempty"`
	Error  string                `json:"error,omitempty"`
}

// BulkEmailVerification handles multiple email verifications
func BulkEmailVerification(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "application/json")

	// Decode the request body
	var req BulkVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid request format"}`, http.StatusBadRequest)
		return
	}

	// Validate input
	if len(req.Emails) == 0 {
		http.Error(w, `{"error": "No emails provided"}`, http.StatusBadRequest)
		return
	}

	if len(req.Emails) > MAX_EMAILS {
		http.Error(w, fmt.Sprintf(`{"error": "Too many emails provided (max %d)"}`, MAX_EMAILS), http.StatusBadRequest)
		return
	}

	// Initialize verifier once for all requests
	verifier := emailVerifier.NewVerifier().
		EnableSMTPCheck().
		Proxy(os.Getenv("PROXY_URL")).
		FromEmail(os.Getenv("FROM_EMAIL")).
		HelloName(os.Getenv("HELO_NAME"))

	// Use wait group and mutex for concurrent processing
	var wg sync.WaitGroup
	results := make([]BulkVerificationResult, 0, len(req.Emails))
	var mu sync.Mutex

	for _, email := range req.Emails {
		wg.Add(1)
		go func(email string) {
			defer wg.Done()

			result, err := verifier.Verify(email)
			res := BulkVerificationResult{Email: email}

			if err != nil {
				res.Error = err.Error()
			} else {
				res.Result = result
			}

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(email)
	}

	wg.Wait()

	// Marshal and return results
	response, err := json.Marshal(results)
	if err != nil {
		http.Error(w, `{"error": "Failed to format response"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(response)
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
	router.POST("/v1/bulk", verifyToken(BulkEmailVerification))

	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Println("Server is running on port 8080...")
	log.Fatal(server.ListenAndServe())
}

func respondWithError(w http.ResponseWriter, status int, errMsg string) {
	response := map[string]string{"error": errMsg}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(response)
}