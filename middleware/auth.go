package middleware

import (
	"net/http"
	// "os"
	// "strings"
)

// CORSMiddleware はCORSを設定する
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//reactUrl := os.Getenv("REACT_URL")

		// 許可したいオリジンのリスト
		// allowlist := []string{reactUrl, "https://himatsumu.kirimaru.org"}
		
		// origin := r.Header.Get("Origin")
		
		// // リクエストのOriginが許可リストに含まれているかを確認
		// isAllowed := false
		// for _, allowedOrigin := range allowlist {
		// 	if strings.EqualFold(origin, allowedOrigin) {
		// 		isAllowed = true
		// 		break
		// 	}
		// }

		// if isAllowed {
		// 	w.Header().Set("Access-Control-Allow-Origin", origin)
		// }
		w.Header().Set("Access-Control-Allow-Origin", "himatsumu.kirimaru.org")
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
