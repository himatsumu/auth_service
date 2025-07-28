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
			UserUuid:     "11111111-1111-1111-1111-111111111111",
			Email:        "testuser1@example.com",
			PasswordHash: testPasswordHash, // 事前に生成したハッシュを使う
			Provider:     "email",
			CreatedAt:    time.Date(2025, 7, 10, 10, 0, 0, 0, time.UTC),
			UpdatedAt:    time.Date(2025, 7, 10, 10, 0, 0, 0, time.UTC),
		},
		{
			UserUuid:     "22222222-2222-2222-2222-222222222222",
			Email:        "testuser2@example.com",
			PasswordHash: testPasswordHash, // 事前に生成したハッシュを使う
			Provider:     "email",
			CreatedAt:    time.Date(2025, 7, 11, 11, 0, 0, 0, time.UTC),
			UpdatedAt:    time.Date(2025, 7, 11, 11, 0, 0, 0, time.UTC),
		},
		{
			UserUuid:     "33333333-3333-3333-3333-333333333333",
			Email:        "googleuser@example.com",
			PasswordHash: "", // Google認証ユーザーはパスワードなし
			Provider:     "google",
			CreatedAt:    time.Date(2025, 7, 12, 12, 0, 0, 0, time.UTC),
			UpdatedAt:    time.Date(2025, 7, 12, 12, 0, 0, 0, time.UTC),
		},
	}
}
