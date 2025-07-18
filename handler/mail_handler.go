package handler

import (
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

func NewMailHandler(s *service.MailService, store *sessions.CookieStore, jwt *service.JWTService) *MailHandler {
	return &MailHandler{Service: s, Store: store, jwt: jwt}
}

// ユーザー登録
func (h *MailHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusBadRequest,
			"message": "値が不正なため登録できません",
		})
		return
	}

	user, err := h.Service.RegisterUser(req.Email, req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusConflict,
			"message": "ユーザーがすでに存在します",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   http.StatusCreated,
		"message":  "ユーザーが登録されました",
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusBadRequest,
			"message": "値が不正なためログインできません",
		})
		return
	}

	user, err := h.Service.VerifyLogin(req.Email, req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusUnauthorized,
			"message": "メールアドレスまたはパスワードが違います",
		})
		return
	}

	token, err := h.jwt.GenerateToken(user)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusInternalServerError,
			"message": "トークンの生成に失敗しました",
		})
		return
	}
	w.Header().Set("Authorization", "Bearer "+token)

	session, _ := h.Store.Get(r, "auth-session")
	session.Values["UserUuid"] = user.UserUuid
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   http.StatusOK,
		"message":  "ログインに成功しました",
		"token":    token,
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
