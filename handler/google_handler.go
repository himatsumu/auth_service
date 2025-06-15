package handler

import (
	"auth-service/service"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth/gothic"
)

type GoogleHandler struct {
	Service *service.GoogleService
	Store   *sessions.CookieStore
}

func NewGoogleHandler(s *service.GoogleService, store *sessions.CookieStore) *GoogleHandler {
	return &GoogleHandler{Service: s, Store: store}
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

	session, _ := h.Store.Get(r, "auth-session")
	session.Values["UserUuid"] = dbUser.UserUuid
	session.Save(r, w)
	http.Redirect(w, r, "http://localhost:3000/dashboard", http.StatusTemporaryRedirect)
}