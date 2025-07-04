package repository

import (
	"auth-service/model"

	"gorm.io/gorm"
)

type GoogleRepository struct {
	DB *gorm.DB
}

// APIのレスポンスとしてクライアントに返すユーザー情報の構造体
func NewGoogleRepository(db *gorm.DB) *GoogleRepository {
	return &GoogleRepository{DB: db}
}

// Googleアカウントからユーザー情報を取得
func (r *GoogleRepository) FindOrCreateUser(email, provider string) (*model.User, error) {
	var user model.User
	result := r.DB.Where(model.User{Email: email, Provider: provider}).FirstOrCreate(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}

func (r *GoogleRepository) FindUserByUUID(uuid string) (*model.User, error) {
	var user model.User
	result := r.DB.First(&user, "user_uuid = ?", uuid)
	return &user, result.Error
}