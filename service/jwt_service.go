package service

import (
	"auth-service/model"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	privateKey *rsa.PrivateKey
	issuer     string
}


type JWTClaims struct {
	UUID string `json:"uuid"`
	jwt.RegisteredClaims
}

func NewJWTService(key *rsa.PrivateKey, issuer string) *JWTService {
	return &JWTService{
		privateKey: key,
		issuer:     issuer,
	}
}

func (s *JWTService) GenerateToken(user *model.User) (string, error) {
	// トークンの有効期限を24時間に設定
	expirationTime := time.Now().Add(24 * time.Hour)

	// クレーム（トークンに含める情報）を設定
	claims := &JWTClaims{
		UUID: user.UserUuid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.issuer,
			Subject:   user.UserUuid, // ユーザーIDをSubjectに設定
		},
	}

	// ヘッダーとクレームから新しいトークンを作成
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// 秘密鍵を使ってトークンに署名
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}