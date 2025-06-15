package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
)

// DBの型宣言
type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

type AuthService struct {
	db    *sql.DB
	store *sessions.CookieStore
}

func main() {
	// 環境変数から設定を取得
	authPort := os.Getenv("AUTH_PORT")
	if authPort == "" {
		authPort = "18080"
	}

	// データベース接続
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("AUTH_DB_NAME")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	// セッションストアの設定
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Fatal("SESSION_SECRET is not set")
	}
	store := sessions.NewCookieStore([]byte(sessionSecret))

	// Gothの設定
	goth.UseProviders(
		google.New(
			os.Getenv("GOOGLE_CLIENT_ID"),
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			os.Getenv("AUTH_CALLBACK_URL")+"/google",
		),
	)

	gothic.Store = store

	// AuthService初期化
	authService := &AuthService{
		db:    db,
		store: store,
	}

	// データベーステーブル作成
	if err := authService.createTables(); err != nil {
		log.Fatal("Failed to create tables:", err)
	}

	// ルーター設定
	r := mux.NewRouter()

	// 認証エンドポイント
	r.HandleFunc("/auth/{provider}", authService.handleAuth).Methods("GET")
	r.HandleFunc("/auth/callback/{provider}", authService.handleAuthCallback).Methods("GET")
	r.HandleFunc("/auth/logout", authService.handleLogout).Methods("POST", "OPTIONS")

	// メール/パスワード認証
	r.HandleFunc("/auth/register", authService.handleRegister).Methods("POST", "OPTIONS")
	r.HandleFunc("/auth/login", authService.handleLogin).Methods("POST", "OPTIONS")

	// ユーザー情報取得
	r.HandleFunc("/user", authService.handleGetUser).Methods("GET")

	// CORS設定
	r.Use(corsMiddleware)

	log.Printf("Auth service starting on port %s", authPort)
	log.Fatal(http.ListenAndServe(":"+authPort, r))
}

func (a *AuthService) createTables() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email VARCHAR(255) UNIQUE NOT NULL,
		name VARCHAR(255) NOT NULL,
		password_hash VARCHAR(255),
		provider VARCHAR(50) DEFAULT 'email',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := a.db.Exec(query)
	return err
}

func (a *AuthService) handleAuth(w http.ResponseWriter, r *http.Request) {
	provider := mux.Vars(r)["provider"]
	
	// セッションにプロバイダーを設定
	session, _ := a.store.Get(r, "auth-session")
	session.Values["provider"] = provider
	session.Save(r, w)

	gothic.BeginAuthHandler(w, r)
}

func (a *AuthService) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// ユーザーをデータベースに保存または更新
	dbUser, err := a.saveOrUpdateUser(user.Email, user.Name, user.Provider)
	if err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	// セッションにユーザーIDを保存
	session, _ := a.store.Get(r, "auth-session")
	session.Values["user_id"] = dbUser.ID
	session.Save(r, w)

	// フロントエンドにリダイレクト
	http.Redirect(w, r, "http://localhost:3000/dashboard", http.StatusTemporaryRedirect)
}

func (a *AuthService) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// パスワードをハッシュ化
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// ユーザーを作成
	query := `INSERT INTO users (email, name, password_hash, provider) VALUES ($1, $2, $3, $4) RETURNING id`
	var userID int
	err = a.db.QueryRow(query, req.Email, req.Name, string(hashedPassword), "email").Scan(&userID)
	if err != nil {
		http.Error(w, "Email already exists or database error", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"user_id": userID,
	})
}

func (a *AuthService) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// ユーザーを検索
	var user User
	var passwordHash string
	query := `SELECT id, email, name, password_hash FROM users WHERE email = $1 AND provider = 'email'`
	err := a.db.QueryRow(query, req.Email).Scan(&user.ID, &user.Email, &user.Name, &passwordHash)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// パスワードを検証
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// セッションにユーザーIDを保存
	session, _ := a.store.Get(r, "auth-session")
	session.Values["user_id"] = user.ID
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"user":    user,
	})
}

func (a *AuthService) handleGetUser(w http.ResponseWriter, r *http.Request) {
	session, _ := a.store.Get(r, "auth-session")
	userID, ok := session.Values["user_id"].(int)
	if !ok {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	var user User
	query := `SELECT id, email, name, provider FROM users WHERE id = $1`
	err := a.db.QueryRow(query, userID).Scan(&user.ID, &user.Email, &user.Name, &user.Provider)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (a *AuthService) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := a.store.Get(r, "auth-session")
	session.Values["user_id"] = nil
	session.Options.MaxAge = -1
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func (a *AuthService) saveOrUpdateUser(email, name, provider string) (*User, error) {
	var user User
	
	// 既存ユーザーをチェック
	query := `SELECT id, email, name, provider FROM users WHERE email = $1 AND provider = $2`
	err := a.db.QueryRow(query, email, provider).Scan(&user.ID, &user.Email, &user.Name, &user.Provider)
	
	if err == sql.ErrNoRows {
		// 新規ユーザーを作成
		insertQuery := `INSERT INTO users (email, name, provider) VALUES ($1, $2, $3) RETURNING id`
		err = a.db.QueryRow(insertQuery, email, name, provider).Scan(&user.ID)
		if err != nil {
			return nil, err
		}
		user.Email = email
		user.Name = name
		user.Provider = provider
	} else if err != nil {
		return nil, err
	}

	return &user, nil
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}