package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid" // UUIDを生成するためにインポート
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// データベースのusersテーブルを表すモデル
type User struct {
	UserUuid     string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"userUuid"`
	Email        string `gorm:"unique;not null" json:"email"`
	PasswordHash string `gorm:"size:255" json:"-"` // パスワードはJSONで返さない
	Provider     string `gorm:"size:50;default:'email'" json:"provider"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserUuidが空の場合に新しいUUIDを自動で設定する
func (user *User) BeforeCreate(tx *gorm.DB) (err error) {
	if user.UserUuid == "" {
		user.UserUuid = uuid.NewString()
	}
	return
}

// APIのレスポンスとしてクライアントに返すユーザー情報
type UserResponse struct {
	UserUuid string `json:"userUuid"` // データ型を string に変更
	Email    string `json:"email"`
	Provider string `json:"provider"`
}

// 認証関連のサービスをまとめた構造体
type AuthService struct {
	db    *gorm.DB
	store *sessions.CookieStore
}

// アプリケーションのエントリーポイント
func main() {
	authPort := os.Getenv("AUTH_PORT")
	if authPort == "" {
		authPort = "18080"
	}

	// データベース接続情報を環境変数から取得
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("AUTH_DB_NAME")

	// データベース接続文字列を生成
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	// GORMを使ってデータベースに接続
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// セッション管理のためのCookieStoreを初期化
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Fatal("SESSION_SECRET is not set")
	}
	store := sessions.NewCookieStore([]byte(sessionSecret))

	// OAuth認証ライブラリ(Goth)の設定, Googleプロバイダーを使用
	goth.UseProviders(
		google.New(
			os.Getenv("GOOGLE_CLIENT_ID"),
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			os.Getenv("AUTH_CALLBACK_URL")+"/google", // 認証後のリダイレクト先
		),
	)
	gothic.Store = store

	// 認証サービスのインスタンスを作成
	authService := &AuthService{
		db:    db,
		store: store,
	}

	// User構造体をもとにusersテーブルを自動生成・更新
	if err := authService.db.AutoMigrate(&User{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// HTTPルーター(mux)を初期化
	r := mux.NewRouter()

	// 各APIエンドポイントと、それを処理する関数(ハンドラ)を紐付け
	r.HandleFunc("/auth/{provider}", authService.handleAuth).Methods("GET")
	r.HandleFunc("/auth/callback/{provider}", authService.handleAuthCallback).Methods("GET")
	r.HandleFunc("/auth/logout", authService.handleLogout).Methods("POST", "OPTIONS")
	r.HandleFunc("/auth/register", authService.handleRegister).Methods("POST", "OPTIONS")
	r.HandleFunc("/auth/login", authService.handleLogin).Methods("POST", "OPTIONS")

	// CORSミドルウェアを設定。異なるオリジン(ドメイン)からのリクエストを許可する
	r.Use(corsMiddleware)

	log.Printf("Auth service starting on port %s", authPort)
	// Webサーバーを起動
	log.Fatal(http.ListenAndServe(":"+authPort, r))
}

// /auth/{provider} へのGETリクエストを処理する
// Googleなどの認証ページへリダイレクトを開始する
func (a *AuthService) handleAuth(w http.ResponseWriter, r *http.Request) {
	provider := mux.Vars(r)["provider"]
	session, _ := a.store.Get(r, "auth-session")
	session.Values["provider"] = provider
	session.Save(r, w)
	gothic.BeginAuthHandler(w, r)
}

// 認証プロバイダーからのコールバックを処理する
func (a *AuthService) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	// 認証プロバイダーからユーザー情報を取得
	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 取得したユーザー情報をデータベースに保存または更新
	dbUser, err := a.saveOrUpdateUser(gothUser.Email, gothUser.Provider)
	if err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	// ユーザーのUUIDをセッションに保存してログイン状態にする
	session, _ := a.store.Get(r, "auth-session")
	session.Values["UserUuid"] = dbUser.UserUuid
	session.Save(r, w)

	// フロントエンドのダッシュボードページにリダイレクト
	http.Redirect(w, r, "http://localhost:3000/dashboard", http.StatusTemporaryRedirect)
}

// handleRegister はメールアドレスとパスワードでの新規登録を処理する
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

	// パスワードをハッシュ化して安全に保存
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// 新しいユーザーを作成
	user := User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Provider:     "email",
	}

	// BeforeCreateフックがここで実行され、user.UserUuidにUUIDが設定される
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

// handleLogin はメールアドレスとパスワードでのログインを処理する
func (a *AuthService) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// メールアドレスを元にユーザーを検索
	var user User
	result := a.db.Where("email = ? AND provider = ?", req.Email, "email").First(&user)
	if result.Error != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// 入力されたパスワードと保存されているハッシュを比較
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// ログイン成功。ユーザーのUUIDをセッションに保存
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

// handleLogout はログアウト処理を行う
func (a *AuthService) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := a.store.Get(r, "auth-session")
	// セッションからユーザーIDを削除
	session.Values["UserUuid"] = nil
	// セッションを即時無効にする
	session.Options.MaxAge = -1
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// saveOrUpdateUser はOAuth認証で取得したユーザー情報をDBに保存または更新する
func (a *AuthService) saveOrUpdateUser(email, provider string) (*User, error) {
	var user User
	// emailとproviderでユーザーを検索し、存在しなければ新しいレコードを作成する
	// 作成時にはBeforeCreateフックが走り、UUIDが設定される
	result := a.db.Where(User{Email: email, Provider: provider}).FirstOrCreate(&user, User{Email: email, Provider: provider})
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

// corsMiddleware はCORS(Cross-Origin Resource Sharing)を設定するミドルウェア
// これにより、http://localhost:3000 のフロントエンドからこのAPIへのリクエストが許可される
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
