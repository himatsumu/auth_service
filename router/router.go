package router

import (
	"auth-service/handler"
	"auth-service/middleware"

	"github.com/gorilla/mux"
)

// 各エンドポイントのhandlerを登録
func NewRouter(mailHandler *handler.MailHandler, googleHandler *handler.GoogleHandler) *mux.Router {
	r := mux.NewRouter()

	// CORSミドルウェアをすべてのルートに適用
	r.Use(middleware.CORSMiddleware)

	// Google認証のルーティング
	r.HandleFunc("/auth/{provider}", googleHandler.HandleAuth).Methods("GET")
	r.HandleFunc("/auth/callback/{provider}", googleHandler.HandleAuthCallback).Methods("GET")
	r.HandleFunc("/auth/user/",  googleHandler.GetUser)

	// メール認証のルーティング
	r.HandleFunc("/auth/register", mailHandler.HandleRegister).Methods("POST", "OPTIONS")
	r.HandleFunc("/auth/login", mailHandler.HandleLogin).Methods("POST", "OPTIONS")
	r.HandleFunc("/auth/logout", mailHandler.HandleLogout).Methods("POST", "OPTIONS")

	return r
}