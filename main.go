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

	"example.com/internal/auth"
	"example.com/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	plat := os.Getenv("PLATFORM")
	jwtSecret := os.Getenv("JWT_SECRET")
	db, _ := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)

	const port = "8080"
	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
		dbQueries:      dbQueries,
		platform:       plat,
		jwtSecret:      jwtSecret,
	}

	mx := http.NewServeMux()
	mx.Handle("GET /app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mx.HandleFunc("GET /api/healthz", handleReadines)
	mx.HandleFunc("GET /admin/metrics", apiCfg.handlerMetrics)
	mx.HandleFunc("POST /admin/reset", apiCfg.handlerReset)
	mx.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		data, err := apiCfg.dbQueries.GetOneRefreshToken(r.Context(), token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if data.ExpiresAt.Before(time.Now()) || (data.RevokedAt.Valid && data.RevokedAt.Time.Before(time.Now())) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		user, err := apiCfg.dbQueries.GetUserFromRefreshToken(r.Context(), token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		newToken, err := auth.MakeJWT(user.ID, apiCfg.jwtSecret)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		response := struct {
			Token string `json:"token"`
		}{
			Token: newToken,
		}
		jsonData, err := json.Marshal(response)
		if err != nil {

			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)

	})
	mx.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		err = apiCfg.dbQueries.RevokeRefreshToken(r.Context(), token)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
	mx.HandleFunc("DELETE /api/chirps/{id}", func(w http.ResponseWriter, r *http.Request) {
		chirpId := r.PathValue("id")
		uuid, err := uuid.Parse(chirpId)
		if err != nil {
			http.Error(w, "Bla", http.StatusInternalServerError)
			return
		}
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			http.Error(w, "ho nooo", http.StatusUnauthorized)
			return
		}
		id, err := auth.ValidateJWT(token, apiCfg.jwtSecret)
		if err != nil {
			http.Error(w, "ho nooo", http.StatusUnauthorized)
			return
		}
		chirp, err := dbQueries.GetAChirp(r.Context(), uuid)
		if chirp.UserID.UUID != id {
			http.Error(w, "asdad", http.StatusForbidden)
			return
		}
		if err != nil {
			http.Error(w, "ho nooo", http.StatusInternalServerError)
			return
		}

		dberr := dbQueries.DeleteChirp(r.Context(), uuid)
		if dberr != nil {
			http.Error(w, "another error", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mx.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		reqPayload := struct {
			Event string `json:"event"`
			Data  struct {
				UserID string `json:"user_id"`
			} `json:"data"`
		}{}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "asdasd", http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(body, &reqPayload); err != nil {
			http.Error(w, "body parsing error", http.StatusInternalServerError)
			return
		}
		if reqPayload.Event != "user.upgraded" {
			w.WriteHeader(http.StatusNoContent)
			return
		} else {
			userUUID, err := uuid.Parse(reqPayload.Data.UserID)
			if err != nil {
				http.Error(w, "Invalid user ID", http.StatusBadRequest)
				return
			}
			_u, err := dbQueries.UpdateUserChirpyRed(r.Context(), database.UpdateUserChirpyRedParams{IsChirpyRed: true, ID: userUUID})
			log.Default().Println(_u)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			} else {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
	})
	mx.HandleFunc("GET /api/chirps/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		uuid, err := uuid.Parse(id)
		if err != nil {
			http.Error(w, "Bla", http.StatusInternalServerError)
			return
		}

		data, err := apiCfg.dbQueries.GetAChirp(r.Context(), uuid)
		if err == sql.ErrNoRows {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "Another error", http.StatusInternalServerError)
			return
		}

		chirp := Chirp{
			ID:        data.ID.String(),
			CreatedAt: data.CreatedAt,
			UpdatedAt: data.UpdatedAt,
			Body:      data.Body,
			UserId:    data.UserID,
		}

		jsonData, err := json.Marshal(chirp)
		if err != nil {
			http.Error(w, "Another error", http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.Write(jsonData)

	})
	mx.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirps, e := apiCfg.dbQueries.GetChirps(r.Context())
		if e != nil {
			http.Error(w, "Bad", http.StatusInternalServerError)
			return
		}

		var chirpList []Chirp
		for _, d := range chirps {
			chirp := Chirp{
				ID:        d.ID.String(),
				CreatedAt: d.CreatedAt,
				UpdatedAt: d.UpdatedAt,
				Body:      d.Body,
				UserId:    d.UserID,
			}
			chirpList = append(chirpList, chirp)
		}

		jsonData, err := json.Marshal(chirpList)
		if err != nil {
			http.Error(w, "Failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)

	})
	mx.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		req := struct {
			Password string `json:"password"`
			Email    string `json:"email"`
		}{}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Failed to parse request body", http.StatusBadRequest)
			return
		}

		user, err := apiCfg.dbQueries.GetUser(r.Context(), req.Email)
		if err != nil {
			http.Error(w, "Failed :)", http.StatusBadRequest)
			return
		}

		if err := auth.CheckPasswordHash(req.Password, user.HashedPassword); err != nil {
			http.Error(w, "Hey now", http.StatusUnauthorized)
			return
		} else {
			token, err := auth.MakeJWT(user.ID, apiCfg.jwtSecret)
			if err != nil {
				http.Error(w, "abc", http.StatusInternalServerError)
				return
			}
			refresh_token, err := auth.MakeRefreshToken()
			if err != nil {
				http.Error(w, "xpto 123", http.StatusInternalServerError)
				return
			}
			_, err = apiCfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{Token: refresh_token, UserID: uuid.NullUUID{UUID: user.ID, Valid: true}})
			if err != nil {
				http.Error(w, "xpto 123456", http.StatusInternalServerError)
				return
			}
			type UserJson struct {
				ID           uuid.UUID `json:"id"`
				CreatedAt    time.Time `json:"created_at"`
				UpdatedAt    time.Time `json:"updated_at"`
				Email        string    `json:"email"`
				Token        string    `json:"token"`
				RefreshToken string    `json:"refresh_token"`
				IsChirpyRed  bool      `json:"is_chirpy_red"`
			}
			payload := UserJson{
				ID:           user.ID,
				CreatedAt:    user.CreatedAt,
				UpdatedAt:    user.UpdatedAt,
				Email:        user.Email,
				Token:        token,
				RefreshToken: refresh_token,
				IsChirpyRed:  user.IsChirpyRed,
			}
			json, err := json.Marshal(payload)
			if err != nil {
				http.Error(w, "HAHAHAHHA", http.StatusInternalServerError)
				return
			}
			w.Header().Add("Content-Type", "application/json")
			w.Write(json)
		}
	})
	mx.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			http.Error(w, "xpto", http.StatusUnauthorized)
			return
		}
		id, err := auth.ValidateJWT(token, apiCfg.jwtSecret)
		if err != nil {
			http.Error(w, "xpto2", http.StatusUnauthorized)
			return
		}
		reqPayload := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "asdasd", http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(body, &reqPayload); err != nil {
			http.Error(w, "body parsing error", http.StatusInternalServerError)
			return
		}
		hashed_pass, err := auth.HashPassword(reqPayload.Password)
		if err != nil {
			http.Error(w, "pass err", http.StatusInternalServerError)
			return
		}
		u := database.UpdateUserParams{Email: reqPayload.Email, HashedPassword: hashed_pass, ID: id}
		d, dberr := dbQueries.UpdateUser(r.Context(), u)
		if dberr != nil {
			http.Error(w, "not possible", http.StatusInternalServerError)
			return
		}
		user := struct {
			ID          string    `json:"id"`
			CreatedAt   time.Time `json:"created_at"`
			UpdatedAt   time.Time `json:"updated_at"`
			Email       string    `json:"email"`
			IsChirpyRed bool      `json:"is_chirpy_red"`
		}{
			ID:          d.ID.String(),
			CreatedAt:   d.CreatedAt,
			UpdatedAt:   d.UpdatedAt,
			Email:       d.Email,
			IsChirpyRed: d.IsChirpyRed,
		}

		p, e := json.Marshal(user)
		if e != nil {
			http.Error(w, "Shit happens 2", http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(p)
	})
	mx.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		reqPayload := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
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
		hashed_pass, err := auth.HashPassword(reqPayload.Password)
		if err != nil {
			http.Error(w, "Ops", http.StatusInternalServerError)
			return
		}
		d, e := apiCfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{Email: reqPayload.Email, HashedPassword: hashed_pass})
		if e != nil {
			http.Error(w, "Shit happens", http.StatusInternalServerError)
			return
		}

		user := struct {
			ID          string    `json:"id"`
			CreatedAt   time.Time `json:"created_at"`
			UpdatedAt   time.Time `json:"updated_at"`
			Email       string    `json:"email"`
			IsChirpyRed bool      `json:"is_chirpy_red"`
		}{
			ID:          d.ID.String(),
			CreatedAt:   d.CreatedAt,
			UpdatedAt:   d.UpdatedAt,
			Email:       d.Email,
			IsChirpyRed: d.IsChirpyRed,
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
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			http.Error(w, "asdsadas", http.StatusUnauthorized)
			return
		}
		id, err := auth.ValidateJWT(token, apiCfg.jwtSecret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		payload := struct {
			Body string `json:"body"`
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
			UserID: uuid.NullUUID{UUID: id, Valid: true},
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
	jwtSecret      string
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

type Chirp struct {
	ID        string        `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Body      string        `json:"body"`
	UserId    uuid.NullUUID `json:"user_id"`
}

// psql "postgres://anderson.correa:@localhost:5432/chirpy"
