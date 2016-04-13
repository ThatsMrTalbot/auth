package auth

import "errors"

type mockStorage struct {
	UID      string
	Username string
	Password string
}

func NewMockStorage(uid string, user string, pass string) Storage {
	return &mockStorage{
		UID:      uid,
		Username: user,
		Password: pass,
	}
}

func (m *mockStorage) GetUser(user string, pass string) (string, error) {
	if m.Username == user && m.Password == pass {
		return m.UID, nil
	}

	return "", errors.New("User not found")
}
