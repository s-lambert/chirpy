package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var loggedInUserId int

func CreateChirpHandler(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		newChirp := Chirp{}
		err := decoder.Decode(&newChirp)

		authorization := r.Header.Get("Authorization")
		if authorization == "" || loggedInUserId == 0 {
			RespondWithError(w, 401, "Unauthorized")
			return
		}

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

		createdChirp, err := db.CreateChirp(strings.Join(bleepedWords, " "), loggedInUserId)
		if err != nil {
			RespondWithError(w, 500, fmt.Sprintf("Failed to create chirp: %s", err.Error()))
			return
		}
		RespondWithJSON(w, 201, createdChirp)
	}
}

func GetChirpsHandler(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chirps, err := db.GetChirps()
		if err != nil {
			RespondWithError(w, 500, fmt.Sprintf("Failed to get chirps: %s", err.Error()))
			return
		}

		authorIdStr := r.URL.Query().Get("author_id")
		if authorIdStr != "" {
			authorId, err := strconv.Atoi(authorIdStr)
			if err != nil {
				RespondWithError(w, 500, "Invalid chirp ID provided.")
				return
			}
			authorChirps := make([]Chirp, 0)
			for _, chirp := range chirps {
				if authorId == chirp.AuthorId {
					authorChirps = append(authorChirps, chirp)
				}
			}

			sortQuery := r.URL.Query().Get("sort")
			if sortQuery == "asc" {
				sort.Slice(authorChirps, func(i, j int) bool { return authorChirps[i].Id < authorChirps[j].Id })
			} else if sortQuery == "desc" {
				sort.Slice(authorChirps, func(i, j int) bool { return authorChirps[i].Id > authorChirps[j].Id })
			}

			RespondWithJSON(w, 200, authorChirps)
			return
		}

		sortQuery := r.URL.Query().Get("sort")
		if sortQuery == "asc" {
			sort.Slice(chirps, func(i, j int) bool { return chirps[i].Id < chirps[j].Id })
		} else if sortQuery == "desc" {
			sort.Slice(chirps, func(i, j int) bool { return chirps[i].Id > chirps[j].Id })
		}

		RespondWithJSON(w, 200, chirps)
	}
}

func GetChirpHandler(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chirpIdStr := r.PathValue("chirpID")
		chirpId, err := strconv.Atoi(chirpIdStr)
		if err != nil {
			RespondWithError(w, 500, "Invalid chirp ID provided.")
			return
		}

		chirp, err := db.GetChirp(chirpId)
		if err != nil {
			RespondWithError(w, 404, fmt.Sprintf("No chirp with id: %s", chirpIdStr))
			return
		}
		RespondWithJSON(w, 200, chirp)
	}
}

func DeleteChirpHandler(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chirpIdStr := r.PathValue("chirpID")
		chirpId, err := strconv.Atoi(chirpIdStr)
		if err != nil {
			RespondWithError(w, 500, "Invalid chirp ID provided.")
			return
		}

		chirp, err := db.GetChirp(chirpId)
		if err != nil {
			RespondWithError(w, 404, fmt.Sprintf("No chirp with id: %s", chirpIdStr))
			return
		}

		authorization := r.Header.Get("Authorization")
		if authorization == "" || loggedInUserId == 0 {
			RespondWithError(w, 401, "Unauthorized")
			return
		}

		authorisedUserId, err := strconv.Atoi(authorization[len(authorization)-1:])
		if err != nil {
			RespondWithError(w, 500, "Invalid auth token")
			return
		}

		if chirp.AuthorId != authorisedUserId {
			RespondWithError(w, 403, "Unauthorized")
			return
		}

		db.DeleteChirp(chirp.Id)

		w.WriteHeader(200)
	}
}

func CreateUserHandler(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		newUser := User{}
		err := decoder.Decode(&newUser)

		w.Header().Set("Content-Type", "application/json")

		if err != nil {
			RespondWithError(w, 500, fmt.Sprintf("Error marshalling JSON: %s", err))
			return
		}

		createdUser, err := db.CreateUser(newUser.Email, newUser.Password)
		if err != nil {
			RespondWithError(w, 500, fmt.Sprintf("Failed to create user: %s", err.Error()))
			return
		}
		RespondWithJSON(w, 201, createdUser)
	}
}

func UpdateUserHandler(db *DB, cfg *ApiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorization := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, err := jwt.ParseWithClaims(authorization, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JwtSecret), nil
		})

		if err != nil {
			fmt.Printf("%s %s\n", authorization, err.Error())
			RespondWithError(w, 401, "Invalid authorization token provided")
			return
		}

		userIdStr, err := token.Claims.GetSubject()
		if err != nil {
			RespondWithError(w, 500, "Token doesn't have subject")
			return
		}

		authorisedUserId, err := strconv.Atoi(userIdStr)
		if err != nil {
			RespondWithError(w, 500, "Couldn't parse token subject into integer")
			return
		}

		type UpdateUserRequest struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		updateUserRequest := UpdateUserRequest{}
		err = decoder.Decode(&updateUserRequest)
		if err != nil {
			RespondWithError(w, 500, "Invalid request")
			return
		}

		updatedUser, err := db.UpdateUser(authorisedUserId, updateUserRequest.Email, updateUserRequest.Password)
		if err != nil {
			RespondWithError(w, 500, "Invalid request")
			return
		}

		updatedUser.Password = ""

		RespondWithJSON(w, 200, updatedUser)
	}
}

func GetUsersHandler(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := db.GetUsers()
		if err != nil {
			RespondWithError(w, 500, fmt.Sprintf("Failed to get users: %s", err.Error()))
			return
		}
		RespondWithJSON(w, 200, users)
	}
}

func GetUserHandler(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userIdStr := r.PathValue("userID")
		userId, err := strconv.Atoi(userIdStr)
		if err != nil {
			RespondWithError(w, 500, "Invalid user ID provided.")
			return
		}

		user, err := db.GetUser(userId)
		if err != nil {
			RespondWithError(w, 404, fmt.Sprintf("No chirp with id: %s", userIdStr))
			return
		}
		RespondWithJSON(w, 200, user)
	}
}

func createToken(jwtSecret string, userId int, expiresInSeconds int) (string, error) {
	mySigningKey := []byte(jwtSecret)

	var expiryTime time.Time
	if expiresInSeconds != 0 {
		expiryTime = time.Now().Add(time.Duration(expiresInSeconds) * time.Second)
	} else {
		expiryTime = time.Now().Add(time.Duration(1) * time.Hour)
	}

	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expiryTime),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "chirpy",
		Subject:   fmt.Sprintf("%d", userId),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(mySigningKey)
}

func createRefreshToken() (string, time.Time) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	s := hex.EncodeToString(b)
	return s, time.Now().Add(time.Duration(60) * time.Hour * 24)
}

func LoginUserHandler(db *DB, cfg *ApiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type LoginRequest struct {
			Email            string `json:"email"`
			Password         string `json:"password"`
			ExpiresInSeconds int    `json:"expires_in_seconds"`
		}
		type LoginResponse struct {
			Id           int    `json:"id"`
			Email        string `json:"email"`
			IsChirpyRed  bool   `json:"is_chirpy_red"`
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}

		decoder := json.NewDecoder(r.Body)
		loginRequest := LoginRequest{}
		err := decoder.Decode(&loginRequest)
		if err != nil {
			RespondWithError(w, 500, fmt.Sprintf("Error marshalling JSON: %s", err))
			return
		}

		user, err := db.GetUserByEmail(loginRequest.Email)

		if err != nil {
			RespondWithError(w, 404, fmt.Sprintf("Could not find user with email: %s", loginRequest.Email))
			return
		}

		if user.Password != loginRequest.Password {
			RespondWithError(w, 401, "Invalid user/password")
			return
		}

		token, err := createToken(cfg.JwtSecret, user.Id, loginRequest.ExpiresInSeconds)
		if err != nil {
			RespondWithError(w, 401, "Could not generate token")
			return
		}

		rToken, exp := createRefreshToken()

		db.SaveRefreshToken(user.Id, rToken, exp)

		loggedInUserId = user.Id
		loginResponse := LoginResponse{
			Id:           user.Id,
			Email:        user.Email,
			IsChirpyRed:  user.IsChirpyRed,
			Token:        token,
			RefreshToken: rToken,
		}
		RespondWithJSON(w, 200, loginResponse)
	}
}

func RefreshTokenHandler(db *DB, cfg *ApiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		userId, err := db.RefreshTokenUser(rToken)
		if err != nil {
			RespondWithError(w, 401, "Invalid/expired token")
			return
		}

		token, err := createToken(cfg.JwtSecret, userId, 0)
		if err != nil {
			RespondWithError(w, 401, "Could not generate token")
			return
		}

		type NewTokenResponse struct {
			Token string `json:"token"`
		}
		RespondWithJSON(w, 200, NewTokenResponse{
			Token: token,
		})
	}
}

func RevokeTokenHandler(db *DB, cfg *ApiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		err := db.RevokeRefreshToken(rToken)
		if err != nil {
			RespondWithError(w, 401, "Invalid/expired token")
			return
		}

		w.WriteHeader(200)
	}
}

func PolkaWebhookHandler(db *DB, cfg *ApiConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type WebhookRequest struct {
			Event string `json:"event"`
			Data  struct {
				UserId int `json:"user_id"`
			} `json:"data"`
		}

		apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "ApiKey ")
		if apiKey != cfg.PolkaKey {
			RespondWithError(w, 401, "Invalid polka key")
			return
		}

		decoder := json.NewDecoder(r.Body)
		webhookReq := WebhookRequest{}
		err := decoder.Decode(&webhookReq)
		if err != nil {
			RespondWithError(w, 500, fmt.Sprintf("Error marshalling JSON: %s", err))
			return
		}

		if webhookReq.Event != "user.upgraded" {
			w.WriteHeader(200)
			return
		}

		err = db.SetChirpyRed(webhookReq.Data.UserId)
		if err != nil {
			RespondWithError(w, 500, err.Error())
		}

		w.WriteHeader(200)
	}
}
