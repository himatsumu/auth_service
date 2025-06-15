package repository

import (
	"gorm.io/gorm"
	"auth-service/model"
)

type MailRepository struct {
	DB *gorm.DB
}

// APIのレスポンスとしてクライアントに返すユーザー情報の構造体
func NewMailRepository(db *gorm.DB) *MailRepository {
	return &MailRepository{DB: db}
}

// ユーザーの作成
func (r *MailRepository) CreateUser(user *model.User) error {
	result := r.DB.Create(user)
	return result.Error
}

// ユーザーの検索
func (r *MailRepository) FindUserByEmail(email string) (*model.User, error) {
	var user model.User
	result := r.DB.Where("email = ? AND provider = ?", email, "email").First(&user)
	return &user, result.Error
}

// ユーザーの検索
func (r *MailRepository) FindUserByUUID(uuid string) (*model.User, error) {
	var user model.User
	result := r.DB.First(&user, "user_uuid = ?", uuid)
	return &user, result.Error
}