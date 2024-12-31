package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"os"

	"github.com/julienschmidt/httprouter"
	"github.com/joho/godotenv"

	emailVerifier "github.com/AfterShip/email-verifier"
)

func GetEmailVerification(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	verifier := emailVerifier.NewVerifier().EnableSMTPCheck().Proxy(os.Getenv("PROXY_URL"))
	ret, err := verifier.Verify(ps.ByName("email"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !ret.Syntax.Valid {
		_, _ = fmt.Fprint(w, "email address syntax is invalid")
		return
	}

	bytes, err := json.Marshal(ret)
	if err != nil {
		http.Error(w, err.Error(), 500)
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

	router := httprouter.New()

	router.GET("/v1/:email/verification", GetEmailVerification)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}