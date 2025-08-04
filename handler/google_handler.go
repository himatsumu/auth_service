package handler

import (
	"auth-service/service"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

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

	// セッションの保存
	session, _ := h.Store.Get(r, "auth-session")
	session.Values["UserUuid"] = dbUser.UserUuid
	session.Values["Provider"] = gothUser.Provider
	session.Values["accessToken"] = gothUser.AccessToken
	err = session.Save(r, w)
	if err != nil {
		fmt.Printf("セッションの保存に失敗しました: %v\n", err)
		http.Error(w, "セッションの保存に失敗しました", http.StatusInternalServerError)
        return
	}

	reactPort := os.Getenv("REACT_PORT")

	redirectUrl := fmt.Sprintf("http://localhost:%s/login", reactPort)

	// リダイレクト
	http.Redirect(w, r, redirectUrl, http.StatusTemporaryRedirect)
}

// セッション情報からJWTを生成して返す
func (h *GoogleHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	// リクエストからセッションを取得
	session, err := h.Store.Get(r, "auth-session")
	if err != nil {
		fmt.Println(err)
		http.Error(w, "セッションの取得に失敗しました", http.StatusInternalServerError)
		return
	}

	// セッションからユーザーUUIDを取得
	userUuid, ok := session.Values["UserUuid"].(string)
	if !ok || userUuid == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  http.StatusUnauthorized,
			"message": "認証情報がありません",
		})
		return
	}

	// UUIDを使ってユーザー情報をデータベースから取得
	user, err := h.Service.GetUserByUUID(userUuid) // 先ほど追加したメソッドを使用
	if err != nil {
		fmt.Println(err)
		http.Error(w, "ユーザーの取得に失敗しました", http.StatusInternalServerError)
		return
	}

	// 新しいJWTを生成
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

	// JWTをJSONレスポンスとして返す
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": http.StatusOK,
		"message": "トークンを生成しました",
		"token":  token,
	})
}

func revokeGoogleToken(accessToken string) error {
	revokeURL := "https://oauth2.googleapis.com/revoke"
	params := url.Values{}
	params.Add("token", accessToken)

	resp, err := http.PostForm(revokeURL, params)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return err
	}
	
	return nil
}