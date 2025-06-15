package handler

import (
	"auth-service/model"
	"auth-service/service"
	"encoding/json"
	"net/http"

	"github.com/gorilla/sessions"
)

type MailHandler struct {
	Service *service.MailService
	Store   *sessions.CookieStore
	jwt     *service.JWTService
}

func NewMailHandler(s *service.MailService, store *sessions.CookieStore , jwt *service.JWTService) *MailHandler {
	return &MailHandler{Service: s, Store: store, jwt: jwt}
}

// ユーザー登録
func (h *MailHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.Service.RegisterUser(req.Email, req.Password)
	if err != nil {
		http.Error(w, "Email already exists or database error", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "User registered successfully",
		"UserUuid": user.UserUuid,
	})
}

// ログイン
func (h *MailHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.Service.VerifyLogin(req.Email, req.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := h.jwt.GenerateToken(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Authorization", "Bearer "+token)

	session, _ := h.Store.Get(r, "auth-session")
	session.Values["UserUuid"] = user.UserUuid
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"user": model.UserResponse{
			UserUuid: user.UserUuid,
			Email:    user.Email,
			Provider: user.Provider,
		},
		"token": token,
	})
}

// ログアウト
func (h *MailHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := h.Store.Get(r, "auth-session")
	session.Values["UserUuid"] = nil
	session.Options.MaxAge = -1
	session.Save(r, w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// ユーザー情報の取得
func (h *MailHandler) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	session, _ := h.Store.Get(r, "auth-session")
	userID, ok := session.Values["UserUuid"].(string)
	if !ok || userID == "" {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	user, err := h.Service.GetUser(userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.UserResponse{
		UserUuid: user.UserUuid,
		Email:    user.Email,
		Provider: user.Provider,
	})
}