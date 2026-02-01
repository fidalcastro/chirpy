package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fidalcastro/chirpy/internal/auth"
	database "github.com/fidalcastro/chirpy/internal/database"
	"github.com/google/uuid"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbUrl          string
	tokenSecret    string
}

type errorResponse struct {
	Error string `json:"error"`
}

type hChirp struct {
	Id        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Body      string `json:"body"`
	UserID    string `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) reset() {
	cfg.fileserverHits.Store(0)
}

func (cfg *apiConfig) getFileserverHits() int {
	return int(cfg.fileserverHits.Load())
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	cfg := &apiConfig{}
	metricsTemplates := `
	<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
	</html>
	`
	mux := http.NewServeMux()

	dbURL := os.Getenv("DB_URL")
	platform := strings.ToLower(os.Getenv("PLATFORM"))
	if platform == "" {
		platform = "dev"
	}
	cfg.dbUrl = dbURL
	cfg.tokenSecret = os.Getenv("JWT_SECRET")
	if cfg.tokenSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}
	fmt.Println("Api Config: ", cfg)

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	dbQueries := database.New(db)

	mux.HandleFunc("GET /app/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "OK")
	})

	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fmt.Sprintf(metricsTemplates, cfg.getFileserverHits()))
	})

	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, r *http.Request) {
		if platform != "dev" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if err := dbQueries.DropUser(r.Context()); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		cfg.reset()
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type reqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := reqBody{}

		if err := decoder.Decode(&params); err != nil {
			httpErrorResponse("Unable to parse email id from request body", err, 500, w)
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			httpErrorResponse("Unable to hash password using argon2id", err, 500, w)
			return
		}

		user, err := dbQueries.CreateUser(r.Context(), database.CreateUserParams{
			Email:          params.Email,
			HashedPassword: hashedPassword,
		})
		if err != nil {
			httpErrorResponse("Unable to create user record for email: "+params.Email, err, 500, w)
			return
		}

		type hUser struct {
			Id        string `json:"id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
			Email     string `json:"email"`
		}

		resp := hUser{
			Id:        user.ID.String(),
			CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt: user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			Email:     user.Email,
		}
		respData, err := json.Marshal(resp)
		if err != nil {
			httpErrorResponse("Unable to marshal user response", err, 500, w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(respData)
	})

	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		type reqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		accessToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			httpErrorResponse("", err, http.StatusUnauthorized, w)
			return
		}

		userId, err := auth.ValidateJWT(accessToken, cfg.tokenSecret)
		if err != nil {
			httpErrorResponse("", err, http.StatusUnauthorized, w)
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := reqBody{}

		if err := decoder.Decode(&params); err != nil {
			httpErrorResponse("Unable to parse email id from request body", err, 500, w)
			return
		}

		hashedPassword, err := auth.HashPassword(params.Password)
		if err != nil {
			httpErrorResponse("", err, http.StatusInternalServerError, w)
			return
		}

		user, err := dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
			ID:             userId,
			HashedPassword: hashedPassword,
			Email:          params.Email,
		})
		if err != nil {
			httpErrorResponse("Failed to update user email/password. Error: ", err, http.StatusInternalServerError, w)
			return
		}

		type hUser struct {
			Id        string `json:"id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
			Email     string `json:"email"`
		}

		resp := hUser{
			Id:        user.ID.String(),
			CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt: user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			Email:     user.Email,
		}
		respData, err := json.Marshal(resp)
		if err != nil {
			httpErrorResponse("Unable to marshal user response", err, 500, w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respData)
	})

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type reqBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := reqBody{}

		if err := decoder.Decode(&params); err != nil {
			httpErrorResponse("Unable to parse email id from request body", err, 500, w)
			return
		}

		user, err := dbQueries.GetUserByEmail(r.Context(), params.Email)
		if err != nil {
			httpErrorResponse("Unable to get user by email: "+params.Email, err, 500, w)
			return
		}
		pMatch, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
		if err != nil {
			httpErrorResponse("Invalid password for email: "+params.Email, err, 401, w)
			return
		}
		if !pMatch {
			httpErrorResponse("Invalid password for email: "+params.Email, nil, 401, w)
			return
		}

		token, err := auth.MakeJWT(user.ID, cfg.tokenSecret)
		if err != nil {
			httpErrorResponse("Unable to create JWT token for user id: "+user.ID.String(), err, 500, w)
			return
		}

		newRefToken, _ := auth.MakeRefreshToken()

		rToken, err := dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
			Token:     newRefToken,
			UserID:    user.ID,
			ExpiresAt: time.Now().AddDate(0, 0, 60),
		})
		if err != nil {
			httpErrorResponse("Unable to create refresh token for user id: "+user.ID.String(), err, 500, w)
			return
		}

		type hUser struct {
			Id           string `json:"id"`
			CreatedAt    string `json:"created_at"`
			UpdatedAt    string `json:"updated_at"`
			Email        string `json:"email"`
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}

		resp := hUser{
			Id:           user.ID.String(),
			CreatedAt:    user.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt:    user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			Email:        user.Email,
			Token:        token,
			RefreshToken: rToken.Token,
		}
		respData, err := json.Marshal(resp)
		if err != nil {
			httpErrorResponse("Unable to marshal user response", err, 500, w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respData)
	})

	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		rToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			httpErrorResponse("Unable to get refresh token", err, 401, w)
			return
		}
		refreshToken, err := dbQueries.GetRefreshToken(r.Context(), rToken)
		if err != nil {
			httpErrorResponse("Unable to get refresh token from database", err, 401, w)
			return
		}

		if refreshToken.RevokedAt.Valid && refreshToken.RevokedAt.Time.Before(time.Now()) {
			httpErrorResponse("Refresh token has been revoked", nil, 401, w)
			return
		}
		if refreshToken.ExpiresAt.Before(time.Now()) {
			httpErrorResponse("Refresh token has expired", nil, 401, w)
			return
		}

		accessToken, err := auth.MakeJWT(refreshToken.UserID, cfg.tokenSecret)
		if err != nil {
			httpErrorResponse("Unable to create new access token", err, 500, w)
			return
		}

		type hRefreshResponse struct {
			AccessToken string `json:"token"`
		}
		resp := hRefreshResponse{
			AccessToken: accessToken,
		}
		respData, err := json.Marshal(resp)
		if err != nil {
			httpErrorResponse("Unable to marshal refresh token response", err, 500, w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respData)
	})

	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		rToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			httpErrorResponse("Unable to get refresh token", err, 401, w)
			return
		}
		_, err = dbQueries.RevokeRefreshToken(r.Context(), rToken)
		if err != nil {
			httpErrorResponse("Unable to revoke refresh token", err, 500, w)
			return
		}
		w.WriteHeader(204)
	})

	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		type reqBody struct {
			Body string `json:"body"`
		}
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			httpErrorResponse("Unable to get bearer token", err, 401, w)
			return
		}

		userId, err := auth.ValidateJWT(token, cfg.tokenSecret)
		if err != nil {
			httpErrorResponse("Unable to validate JWT token", err, 401, w)
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := reqBody{}

		if err := decoder.Decode(&params); err != nil {
			httpErrorResponse("Unable to parse chirp from request body", err, 500, w)
			return
		}

		if len(params.Body) == 0 {
			httpErrorResponse("Chirp is too small or can not be empty", nil, 500, w)
			return
		}

		// If chirp is too long
		if len(params.Body) > 140 {
			httpErrorResponse("Chirp is too long", nil, 400, w)
			return
		}

		// Censoring bad words
		body := []string{}
		for _, word := range strings.Split(params.Body, " ") {
			if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
				body = append(body, "****")
				continue
			}
			body = append(body, word)
		}

		chirp, err := dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   strings.Join(body, " "),
			UserID: userId,
		})
		if err != nil {
			httpErrorResponse("Unable to create chirp", err, 500, w)
			return
		}

		resp := hChirp{
			Id:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
		}

		respData, err := json.Marshal(resp)
		if err != nil {
			httpErrorResponse("Unable to marshal chirp response", err, 500, w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(respData)
	})

	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		var result []hChirp

		chirpsList, err := dbQueries.ListChirps(r.Context())
		if err != nil {
			httpErrorResponse("Unable to list all chirps", err, 500, w)
			return
		}

		for _, chirp := range chirpsList {
			result = append(result, hChirp{
				Id:        chirp.ID.String(),
				CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z"),
				UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z"),
				Body:      chirp.Body,
				UserID:    chirp.UserID.String(),
			})
		}

		respData, err := json.Marshal(result)
		if err != nil {
			httpErrorResponse("Unable to marshal list chirp response", err, 500, w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respData)
	})

	mux.HandleFunc("GET /api/chirps/{id}", func(w http.ResponseWriter, r *http.Request) {
		chirpId := r.PathValue("id")
		if len(chirpId) == 0 {
			httpErrorResponse("Chirp id can not be empty", nil, 500, w)
			return
		}

		cId, err := uuid.Parse(chirpId)
		if err != nil {
			httpErrorResponse("Unable to parse chirp id", err, 400, w)
			return
		}

		chirp, err := dbQueries.GetChirp(r.Context(), cId)
		if err != nil {
			httpErrorResponse("Unable to get chirp by id: "+chirpId, err, 404, w)
			return
		}

		resp := hChirp{
			Id:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
		}

		respData, err := json.Marshal(resp)
		if err != nil {
			httpErrorResponse("Unable to marshal chirp response", err, 500, w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(respData)
	})

	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("./")))))

	httpServer := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Fatal(httpServer.ListenAndServe())
}

func httpErrorResponse(userMsg string, userErr error, statusCode int, w http.ResponseWriter) {
	var msg string = userMsg
	if userErr != nil {
		msg = fmt.Sprintf("%s. Error: %v", msg, userErr)
	}

	errResp := errorResponse{
		Error: msg,
	}

	respData, err := json.Marshal(errResp)
	if err != nil {
		log.Printf("Failed to marshal error response: %v", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(respData)
}
