package main

import (
	"auth-service/database"
	"auth-service/handler"
	"auth-service/model"
	"auth-service/repository"
	"auth-service/router" // routerパッケージをインポート
	"auth-service/service"
	"auth-service/util"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

func main() {
	// 起動前処理
	if err := savePrivateKeyFromEnv(); err != nil {
		log.Fatalf("Failed to save private key: %v", err)
	}

	// データベース接続
	db, err := database.ConnectDB()
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKey, err := util.LoadPrivateKey("keys/private.key")
	if err != nil {
		log.Fatal(err.Error())
	}

	// JWTサービスの初期化
	jwtService := service.NewJWTService(privateKey, "auth-service")

	// データベースのマイグレーション
	db.AutoMigrate(&model.User{})

	database.Testdata(db)

	// 依存関係の初期化 (DI: Dependency Injection)
	// repository -> service -> handler の順でインスタンスを生成
	mailRepo := repository.NewMailRepository(db)
	googleRepo := repository.NewGoogleRepository(db)

	mailService := service.NewMailService(mailRepo)
	googleService := service.NewGoogleService(googleRepo)

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		log.Fatal("SESSION_SECRET is not set")
	}
	store := sessions.NewCookieStore([]byte(sessionSecret))

	mailHandler := handler.NewMailHandler(mailService, store, jwtService)
	googleHandler := handler.NewGoogleHandler(googleService, store, jwtService)

	// Goth (OAuth) の設定
	goth.UseProviders(
		google.New(
			os.Getenv("GOOGLE_CLIENT_ID"),
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			os.Getenv("AUTH_CALLBACK_URL")+"/google",
		),
	)
	gothic.Store = store


	// ルーターの初期化
	r := router.NewRouter(mailHandler, googleHandler)

	// サーバー起動
	authPort := os.Getenv("AUTH_PORT")
	if authPort == "" {
		authPort = "18080"
	}
	log.Printf("Auth service starting on port %s", authPort)
	log.Fatal(http.ListenAndServe(":"+authPort, r))
}

// 起動時に一度だけ実行するヘルパー関数
func savePrivateKeyFromEnv() error {
	encodedKey := os.Getenv("PRIVATE_KEY_FILE")
	if encodedKey == "" {
		return fmt.Errorf("environment variable PRIVATE_KEY_FILE is not set")
	}
	decodedKey, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return fmt.Errorf("failed to decode base64 private key: %w", err)
	}
	if err := os.MkdirAll("keys", 0755); err != nil {
		return fmt.Errorf("failed to create keys directory: %w", err)
	}
	filePath := "keys/private.key"
	if err := os.WriteFile(filePath, decodedKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key to file: %w", err)
	}
	log.Printf("Successfully saved private key to %s", filePath)
	return nil
}