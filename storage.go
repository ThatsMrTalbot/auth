package auth

// Storage implements account storage
type Storage interface {
	GetUser(user string, pass string) (string, error)
}
