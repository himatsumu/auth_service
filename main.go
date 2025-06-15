package main

import (
	"encoding/base64" // Base64のデコードに必要
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	UserUuid     string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"userUuid"`
	Email        string    `gorm:"unique;not null" json:"email"`
	PasswordHash string    `gorm:"size:255" json:"-"`
	Provider     string    `gorm:"size:50;default:'email'" json:"provider"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (user *User) BeforeCreate(tx *gorm.DB) (err error) {
	if user.UserUuid == "" {
		user.UserUuid = uuid.NewString()
	}
	return
}

type UserResponse struct {
	UserUuid string `json:"userUuid"`
	Email    string `json:"email"`
	Provider string `json:"provider"`
}

type AuthService struct {
	db    *gorm.DB
	store *sessions.CookieStore
}

// main はアプリケーションのエントリーポイント
func main() {
	// アプリケーション起動時に秘密鍵をファイルとして保存する
	if err := savePrivateKeyFromEnv(); err != nil {
		log.Fatalf("Failed to save private key: %v", err)
	}

	authPort := os.Getenv("AUTH_PORT")
	if authPort == "" {
		authPort = "18080"
	}

	// (以降のmain関数の処理は変更なし)
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("AUTH_DB_NAME")

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Fatal("SESSION_SECRET is not set")
	}
	store := sessions.NewCookieStore([]byte(sessionSecret))

	goth.UseProviders(
		google.New(
			os.Getenv("GOOGLE_CLIENT_ID"),
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			os.Getenv("AUTH_CALLBACK_URL")+"/google",
		),
	)

	gothic.Store = store

	authService := &AuthService{
		db:    db,
		store: store,
	}

	if err := authService.db.AutoMigrate(&User{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/auth/{provider}", authService.handleAuth).Methods("GET")
	r.HandleFunc("/auth/callback/{provider}", authService.handleAuthCallback).Methods("GET")
	r.HandleFunc("/auth/logout", authService.handleLogout).Methods("POST", "OPTIONS")
	r.HandleFunc("/auth/register", authService.handleRegister).Methods("POST", "OPTIONS")
	r.HandleFunc("/auth/login", authService.handleLogin).Methods("POST", "OPTIONS")
	r.HandleFunc("/user", authService.handleGetUser).Methods("GET")
	r.Use(corsMiddleware)

	log.Printf("Auth service starting on port %s", authPort)
	log.Fatal(http.ListenAndServe(":"+authPort, r))
}

// 環境変数からBase64エンコードされた秘密鍵を読み込み、デコードしてファイルに保存する関数
func savePrivateKeyFromEnv() error {
	// PRIVATE_KEY_FILEからBase64文字列を取得
	encodedKey := os.Getenv("PRIVATE_KEY_FILE")
	if encodedKey == "" {
		return fmt.Errorf("environment variable PRIVATE_KEY_FILE is not set")
	}

	// Base64文字列をデコードする
	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return fmt.Errorf("failed to decode base64 private key: %w", err)
	}

	// keysディレクトリを作成する
	if err := os.MkdirAll("keys", 0755); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}

	// 4. デコードした鍵を書き込む
	// パーミッション 0600 は、所有者のみが読み書きできる設定で、秘密鍵の保存に推奨される
	filePath := "keys/private.key"
	if err := os.WriteFile(filePath, decodedKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}

	log.Printf("Successfully saved private key to %s", filePath)
	return nil
}

func (a *AuthService) handleAuth(w http.ResponseWriter, r *http.Request) {
	provider := mux.Vars(r)["provider"]
	session, _ := a.store.Get(r, "auth-session")
	session.Values["provider"] = provider
	session.Save(r, w)
	gothic.BeginAuthHandler(w, r)
}

func (a *AuthService) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dbUser, err := a.saveOrUpdateUser(gothUser.Email, gothUser.Provider)
	if err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	session, _ := a.store.Get(r, "auth-session")
	session.Values["UserUuid"] = dbUser.UserUuid
	session.Save(r, w)
	http.Redirect(w, r, "http://localhost:3000/dashboard", http.StatusTemporaryRedirect)
}

func (a *AuthService) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Provider:     "email",
	}

	result := a.db.Create(&user)
	if result.Error != nil {
		http.Error(w, "Email already exists or database error", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "User registered successfully",
		"UserUuid": user.UserUuid,
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

	var user User
	result := a.db.Where("email = ? AND provider = ?", req.Email, "email").First(&user)
	if result.Error != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	session, _ := a.store.Get(r, "auth-session")
	session.Values["UserUuid"] = user.UserUuid
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"user": UserResponse{
			UserUuid: user.UserUuid,
			Email:    user.Email,
			Provider: user.Provider,
		},
	})
}

func (a *AuthService) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := a.store.Get(r, "auth-session")
	session.Values["UserUuid"] = nil
	session.Options.MaxAge = -1
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func (a *AuthService) saveOrUpdateUser(email, provider string) (*User, error) {
	var user User
	result := a.db.Where(User{Email: email, Provider: provider}).FirstOrCreate(&user, User{Email: email, Provider: provider})
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func (a *AuthService) handleGetUser(w http.ResponseWriter, r *http.Request) {
	session, _ := a.store.Get(r, "auth-session")
	// セッションからUUID(string)を取得
	userID, ok := session.Values["UserUuid"].(string)
	if !ok || userID == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// UUIDを元にユーザー情報をデータベースから取得
	var user User
	result := a.db.First(&user, "user_uuid = ?", userID)
	if result.Error != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{
		UserUuid: user.UserUuid,
		Email:    user.Email,
		Provider: user.Provider,
	})
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