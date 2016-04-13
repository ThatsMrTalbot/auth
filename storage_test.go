package auth

import "errors"

type mockStorage struct {
	UID         string
	Username    string
	Password    string
	Permissions []string
}

func NewMockStorage(uid string, user string, pass string, permissions []string) Storage {
	return &mockStorage{
		UID:         uid,
		Username:    user,
		Password:    pass,
		Permissions: permissions,
	}
}

func (m *mockStorage) Authenticate(user string, pass string) (*User, error) {
	if m.Username == user && m.Password == pass {
		return NewMockUser(m.UID, m.Permissions...), nil
	}

	return nil, errors.New("User not found")
}

func NewMockUser(uid string, permissions ...string) *User {
	return &User{
		UID:         uid,
		Permissions: permissions,
	}
}
