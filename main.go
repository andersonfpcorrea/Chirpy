package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"example.com/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	plat := os.Getenv("PLATFORM")
	db, _ := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)

	const port = "8080"
	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
		dbQueries:      dbQueries,
		platform:       plat,
	}

	mx := http.NewServeMux()
	mx.Handle("GET /app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mx.HandleFunc("GET /api/healthz", handleReadines)
	mx.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)
	mx.HandleFunc("POST /admin/reset", apiCfg.handlerReset)
	mx.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		reqPayload := struct {
			Email string `json:"email"`
		}{}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Unable to read request body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &reqPayload); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		d, e := apiCfg.dbQueries.CreateUser(r.Context(), reqPayload.Email)
		if e != nil {
			http.Error(w, "Shit happens", http.StatusInternalServerError)
			return
		}

		user := struct {
			ID        string    `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			Email     string    `json:"email"`
		}{
			ID:        d.ID.String(),
			CreatedAt: d.CreatedAt,
			UpdatedAt: d.UpdatedAt,
			Email:     d.Email,
		}

		p, e := json.Marshal(user)
		if e != nil {
			http.Error(w, "Shit happens 2", http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(p)
	})

	mx.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		payload := struct {
			Body   string        `json:"body"`
			UserId uuid.NullUUID `json:"user_id"`
		}{}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}

		if len(payload.Body) > 140 {
			type errorMsg struct {
				Error string `json:"error"`
			}
			errMsg := errorMsg{
				Error: "Chirp is too long",
			}
			dat, _ := json.Marshal(errMsg)
			w.WriteHeader(http.StatusBadRequest)
			w.Write(dat)
		}

		profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
		for _, word := range profaneWords {
			r := regexp.MustCompile(`(?i)` + word)
			payload.Body = r.ReplaceAllString(payload.Body, "****")
		}

		d, err := apiCfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   payload.Body,
			UserID: payload.UserId,
		})
		if err != nil {
			http.Error(w, "Error creating chirp", http.StatusInternalServerError)
			return
		}

		chirp := struct {
			ID        string        `json:"id"`
			CreatedAt time.Time     `json:"created_at"`
			UpdatedAt time.Time     `json:"updated_at"`
			Body      string        `json:"body"`
			UserId    uuid.NullUUID `json:"user_id"`
		}{
			ID:        d.ID.String(),
			CreatedAt: d.CreatedAt,
			UpdatedAt: d.UpdatedAt,
			Body:      d.Body,
			UserId:    d.UserID,
		}

		respBody, err := json.Marshal(chirp)
		if err != nil {
			http.Error(w, "Something went wrong x)", http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(respBody)
	})

	srv := &http.Server{
		Addr:    "localhost:" + port,
		Handler: mx,
	}

	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}

func handleReadines(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	cfg.fileserverHits.Store(0)
	if e := cfg.dbQueries.DeleteAllUsers(r.Context()); e != nil {
		http.Error(w, "Reset failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(fmt.Sprintf(`
	<html>
		<body>
			<h1>Welcome, Chirpy Admin</h1>
			<p>Chirpy has been visited %d times!</p>
		</body>
	</html>`, cfg.fileserverHits.Load())))
}

func middlewareLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// psql "postgres://anderson.correa:@localhost:5432/chirpy"
