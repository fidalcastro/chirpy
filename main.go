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

	database "github.com/fidalcastro/chirpy/internal/database"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
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
	// error respsonse
	type errorResponse struct {
		Error string `json:"error"`
	}

	fmt.Println(cfg.fileserverHits.Load())
	mux := http.NewServeMux()

	dbURL := os.Getenv("DB_URL")
	fmt.Println(dbURL)
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
		cfg.reset()
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type reqBody struct {
			Email string `json:"email"`
		}

		decoder := json.NewDecoder(r.Body)
		params := reqBody{}

		if err := decoder.Decode(&params); err != nil {
			resp := errorResponse{
				Error: "Unable to parse email id from request body",
			}
			respData, err := json.Marshal(resp)

			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			w.Write(respData)
			return
		}

		user, err := dbQueries.CreateUser(r.Context(), params.Email)
		if err != nil {
			resp := errorResponse{
				Error: "Unable to create user record for email: " + params.Email + ". Err: " + err.Error(),
			}
			respData, err := json.Marshal(resp)

			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			w.Write(respData)
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
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(respData)
	})

	mux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		// Valid Respoonse
		type validResponse struct {
			Valid bool `json:"valid"`
		}

		type cleanedBody struct {
			CleanedBody string `json:"cleaned_body"`
		}

		// request
		type reqBody struct {
			Body string `json:"body"`
		}

		// decode request
		decoder := json.NewDecoder(r.Body)
		params := reqBody{}
		if err := decoder.Decode(&params); err != nil {
			resp := errorResponse{
				Error: "Something went wrong",
			}
			respData, err := json.Marshal(resp)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			w.Write(respData)
			return
		}

		if len(params.Body) == 0 {
			resp := errorResponse{
				Error: "Chirp is too small or can not be empty",
			}
			respData, err := json.Marshal(resp)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			w.Write(respData)
			return

		}

		// If chirp is too long
		if len(params.Body) > 140 {
			resp := errorResponse{
				Error: "Chirp is too long",
			}
			respData, err := json.Marshal(resp)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			w.Write(respData)
			return
		}

		/*resp := validResponse{
			Valid: true,
		}*/

		body := []string{}
		for _, word := range strings.Split(params.Body, " ") {
			if strings.ToLower(word) == "kerfuffle" || strings.ToLower(word) == "sharbert" || strings.ToLower(word) == "fornax" {
				body = append(body, "****")
				continue
			}
			body = append(body, word)
		}
		resp := cleanedBody{
			CleanedBody: strings.Join(body, " "),
		}

		respData, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(respData)

	})
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("./")))))

	httpServer := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Fatal(httpServer.ListenAndServe())
}
