package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type apiConfig struct {
	fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits += 1

		next.ServeHTTP(w, r)
	})
}

func middlewareNoCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	corsMux := middlewareCors(mux)

	cfg := apiConfig{
		fileserverHits: 0,
	}

	mux.Handle("/app/", middlewareNoCache(cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir("public"))))))
	mux.Handle("GET /api/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, `OK`)
	}))
	mux.Handle("GET /admin/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html>

<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>

</html>
`, cfg.fileserverHits)
	}))
	mux.Handle("/api/reset", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits = 0
	}))
	mux.Handle("POST /api/validate_chirp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	http.ListenAndServe(":8080", corsMux)
}
