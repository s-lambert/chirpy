package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

func RespondWithError(w http.ResponseWriter, code int, msg string) {
	type chirpError struct {
		Error string `json:"error"`
	}

	somethingWentWrong := chirpError{
		Error: msg,
	}
	wrongResponse, err := json.Marshal(somethingWentWrong)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.WriteHeader(code)
	w.Write(wrongResponse)
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	validResponse, err := json.Marshal(payload)
	if err != nil {
		RespondWithError(w, 500, fmt.Sprintf("Error marshalling JSON: %s", err))
		return
	}
	w.WriteHeader(code)
	w.Write(validResponse)
}
