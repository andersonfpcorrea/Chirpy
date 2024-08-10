package main

import (
	"log"
	"net/http"
)

func main() {
	const port = "8080"

	mx := http.NewServeMux()

	srv := &http.Server{
		Addr:    "localhost:" + port,
		Handler: mx,
	}

	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}
