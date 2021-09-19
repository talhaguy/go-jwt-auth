package repository

type UserRepository interface {
	GetByUserName(username string) (*User, error)
	Save(username string, hashedPassword string) error
}

var userDb = make(map[string]string)

type DefaultUserRepository struct {
}

func NewDefaultUserRepository() *DefaultUserRepository {
	return &DefaultUserRepository{}
}

func (u *DefaultUserRepository) GetByUserName(username string) (*User, error) {
	hashedPass, ok := userDb[username]
	if !ok {
		return &User{}, &NotFoundError{}
	}

	return &User{
		Username:       username,
		HashedPassword: hashedPass,
	}, nil
}

func (u *DefaultUserRepository) Save(username string, hashedPassword string) error {
	userDb[username] = hashedPassword
	return nil
}

type User struct {
	Id             string
	Username       string
	HashedPassword string
}
