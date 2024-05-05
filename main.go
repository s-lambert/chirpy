package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

type ApiConfig struct {
	fileserverHits int
	JwtSecret      string
	PolkaKey       string
}

func (cfg *ApiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
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

	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")
	cfg := ApiConfig{
		fileserverHits: 0,
		JwtSecret:      jwtSecret,
		PolkaKey:       polkaKey,
	}

	db, err := NewDB("database.json")
	if err != nil {
		log.Fatal(err)
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
	mux.Handle("GET /api/chirps", GetChirpsHandler(db))
	mux.Handle("POST /api/chirps", CreateChirpHandler(db))
	mux.Handle("DELETE /api/chirps/{chirpID}", DeleteChirpHandler(db))
	mux.Handle("GET /api/chirps/{chirpID}", GetChirpHandler(db))
	mux.Handle("GET /api/users", GetUsersHandler(db))
	mux.Handle("POST /api/users", CreateUserHandler(db))
	mux.Handle("PUT /api/users", UpdateUserHandler(db, &cfg))
	mux.Handle("GET /api/users/{userID}", GetUserHandler(db))
	mux.Handle("POST /api/login", LoginUserHandler(db, &cfg))
	mux.Handle("POST /api/refresh", RefreshTokenHandler(db, &cfg))
	mux.Handle("POST /api/revoke", RevokeTokenHandler(db, &cfg))
	mux.Handle("POST /api/polka/webhooks", PolkaWebhookHandler(db, &cfg))
	http.ListenAndServe(":8080", corsMux)
}
