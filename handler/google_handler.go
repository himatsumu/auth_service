package handler

import (
	"auth-service/service"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth/gothic"
)

type GoogleHandler struct {
	Service *service.GoogleService
	Store   *sessions.CookieStore
	jwt     *service.JWTService
}

func NewGoogleHandler(s *service.GoogleService, store *sessions.CookieStore, jwt *service.JWTService) *GoogleHandler {
	return &GoogleHandler{Service: s, Store: store, jwt: jwt}
}

// Google認証ページへのリダイレクトを開始
func (h *GoogleHandler) HandleAuth(w http.ResponseWriter, r *http.Request) {
	provider := mux.Vars(r)["provider"]
	session, _ := h.Store.Get(r, "auth-session")
	session.Values["provider"] = provider
	session.Save(r, w)
	gothic.BeginAuthHandler(w, r)
}

// Google認証後のコールバック
func (h *GoogleHandler) HandleAuthCallback(w http.ResponseWriter, r *http.Request) {
	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": "google認証に失敗しました",
		})
		return
	}

	dbUser, err := h.Service.ProcessUser(gothUser.Email, gothUser.Provider)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": "ユーザーの登録に失敗しました",
		})
		return
	}

	token, err := h.jwt.GenerateToken(dbUser)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": "トークンの生成に失敗しました",
		})
		return
	}
	// セッションの保存
	session, _ := h.Store.Get(r, "auth-session")
	session.Values["UserUuid"] = dbUser.UserUuid
	session.Save(r, w)

	// JSON レスポンスを返す
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":   token,
		"user": map[string]interface{}{
			"uuid":     dbUser.UserUuid,
			"provider": dbUser.Provider,
		},
		"message": "認可に成功しました",
	})
}