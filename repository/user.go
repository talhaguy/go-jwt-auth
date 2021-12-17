package repository

type UserRepository interface {
	GetByUserName(username string) (*User, error)
	Save(username string, hashedPassword string) error
}

var inMemoryUserDb = make(map[string]string)

type InMemoryUserRepository struct {
}

func NewInMemoryUserRepository() *InMemoryUserRepository {
	return &InMemoryUserRepository{}
}

func (r *InMemoryUserRepository) GetByUserName(username string) (*User, error) {
	hashedPass, ok := inMemoryUserDb[username]
	if !ok {
		return &User{}, &NotFoundError{}
	}

	return &User{
		Username:       username,
		HashedPassword: hashedPass,
	}, nil
}

func (r *InMemoryUserRepository) Save(username string, hashedPassword string) error {
	inMemoryUserDb[username] = hashedPassword
	return nil
}

type User struct {
	Id             string
	Username       string
	HashedPassword string
}
