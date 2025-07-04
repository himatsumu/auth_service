package service

import (
	"auth-service/model"
	"auth-service/repository"
)

type GoogleService struct {
	Repo *repository.GoogleRepository
}

// APIのレスポンスとしてクライアントに返すユーザー情報の構造体
func NewGoogleService(repo *repository.GoogleRepository) *GoogleService {
	return &GoogleService{Repo: repo}
}

// Googleアカウントからユーザー情報を取得
func (s *GoogleService) ProcessUser(email, provider string) (*model.User, error) {
	return s.Repo.FindOrCreateUser(email, provider)
}

// ユーザー情報の取得
func (s *GoogleService) GetUserByUUID(uuid string) (*model.User, error) {
	return s.Repo.FindUserByUUID(uuid)
}