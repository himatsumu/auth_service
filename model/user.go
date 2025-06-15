package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DBのuserテーブルを表すモデル
type User struct {
	UserUuid     string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"userUuid"`
	Email        string    `gorm:"unique;not null" json:"email"`
	PasswordHash string    `gorm:"size:255" json:"-"`
	Provider     string    `gorm:"size:50;default:'email'" json:"provider"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UUIDの生成
func (user *User) BeforeCreate(tx *gorm.DB) (err error) {
	if user.UserUuid == "" {
		user.UserUuid = uuid.NewString()
	}
	return
}

// APIのレスポンスとしてクライアントに返すユーザー情報の構造体
type UserResponse struct {
	UserUuid string `json:"userUuid"`
	Email    string `json:"email"`
	Provider string `json:"provider"`
}