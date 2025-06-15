package service

import (
	"auth-service/model"
	"auth-service/repository"

	"golang.org/x/crypto/bcrypt"
)

type MailService struct {
	Repo *repository.MailRepository
}

// APIのレスポンスとしてクライアントに返すユーザー情報の構造体
func NewMailService(repo *repository.MailRepository) *MailService {
	return &MailService{Repo: repo}
}

// ユーザー作成
func (s *MailService) RegisterUser(email, password string) (*model.User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Email:        email,
		PasswordHash: string(hashedPassword),
		Provider:     "email",
	}

	err = s.Repo.CreateUser(user)
	return user, err
}

// ユーザー認証
func (s *MailService) VerifyLogin(email, password string) (*model.User, error) {
	user, err := s.Repo.FindUserByEmail(email)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, err // パスワード不一致
	}
	return user, nil
}

// ユーザー情報の取得
func (s *MailService) GetUser(uuid string) (*model.User, error) {
	return s.Repo.FindUserByUUID(uuid)
}