package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func ValidateChirp(w http.ResponseWriter, r *http.Request) {
	type chirp struct {
		Body string `json:"body"`
	}
	type chirpSuccess struct {
		CleanedBody string `json:"cleaned_body"`
	}

	decoder := json.NewDecoder(r.Body)
	newChirp := chirp{}
	err := decoder.Decode(&newChirp)

	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		RespondWithError(w, 500, fmt.Sprintf("Error marshalling JSON: %s", err))
		return
	}

	if len([]rune(newChirp.Body)) > 140 {
		RespondWithError(w, 400, "Chirp is too long")
		return
	}

	swearWords := []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}

	words := strings.Split(newChirp.Body, " ")
	bleepedWords := make([]string, 0)

	for _, word := range words {
		shouldBleep := false
		lowerWord := strings.ToLower(word)
		for _, swearWord := range swearWords {
			if lowerWord == swearWord {
				shouldBleep = true
				break
			}
		}
		if shouldBleep {
			bleepedWords = append(bleepedWords, "****")
		} else {
			bleepedWords = append(bleepedWords, word)
		}
	}

	isValidChirp := chirpSuccess{
		CleanedBody: strings.Join(bleepedWords, " "),
	}
	RespondWithJSON(w, 200, isValidChirp)
}
