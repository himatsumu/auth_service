package handler

import (
	"auth-service/service"
	"net/http"
	"net/url"

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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	dbUser, err := h.Service.ProcessUser(gothUser.Email, gothUser.Provider)
	if err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	token, err := h.jwt.GenerateToken(dbUser)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Authorization", "Bearer "+token)

	session, _ := h.Store.Get(r, "auth-session")
	session.Values["UserUuid"] = dbUser.UserUuid
	session.Save(r, w)

	redirectURL := "http://localhost:3000/dashboard"
	u, _ := url.Parse(redirectURL)
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
}