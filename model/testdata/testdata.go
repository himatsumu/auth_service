package testdata

import (
	"auth-service/model"
	"time"

	"log"

	"golang.org/x/crypto/bcrypt"
)

const TestPassword = "password123"

// パスワードハッシュを格納する変数
var testPasswordHash string

// UserTestData はDBに投入するテストユーザーのデータ
// ここでは宣言のみ行い、初期化はinit()関数内で行う
var UserTestData []model.User

func init() {
	// bcrypt.GenerateFromPasswordは (ハッシュ, エラー) の2つの値を返す
	hashedPasswordBytes, err := bcrypt.GenerateFromPassword([]byte(TestPassword), bcrypt.DefaultCost)
	if err != nil {
		// ハッシュ生成に失敗した場合はテストを続行できないので、プログラムを停止する
		log.Fatalf("Could not hash test password: %v", err)
	}
	testPasswordHash = string(hashedPasswordBytes)

	// ★★★ ハッシュを生成した後に、テストデータを初期化する ★★★
	UserTestData = []model.User{
		{
			UserUuid:     "a1b2c3d4-e5f6-7777-8888-999a0b1c2d3e",
			Email:        "testuser1@example.com",
			PasswordHash: testPasswordHash, // 事前に生成したハッシュを使う
			Provider:     "email",
			CreatedAt:    time.Date(2025, 7, 10, 10, 0, 0, 0, time.UTC),
			UpdatedAt:    time.Date(2025, 7, 10, 10, 0, 0, 0, time.UTC),
		},
		{
			UserUuid:     "f0e9d8c7-b6a5-4444-3333-22b1a0c9d8e7",
			Email:        "testuser2@example.com",
			PasswordHash: testPasswordHash, // 事前に生成したハッシュを使う
			Provider:     "email",
			CreatedAt:    time.Date(2025, 7, 11, 11, 0, 0, 0, time.UTC),
			UpdatedAt:    time.Date(2025, 7, 11, 11, 0, 0, 0, time.UTC),
		},
		{
			UserUuid:     "12345678-90ab-cdef-1234-567890abcdef",
			Email:        "googleuser@example.com",
			PasswordHash: "", // Google認証ユーザーはパスワードなし
			Provider:     "google",
			CreatedAt:    time.Date(2025, 7, 12, 12, 0, 0, 0, time.UTC),
			UpdatedAt:    time.Date(2025, 7, 12, 12, 0, 0, 0, time.UTC),
		},
	}
}
