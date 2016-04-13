package auth

// User contains uid and permissions
type User struct {
	UID         string
	Permissions []string
}

// Storage implements account storage
type Storage interface {
	Authenticate(user string, pass string) (*User, error)
}
