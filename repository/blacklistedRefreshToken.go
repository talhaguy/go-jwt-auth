package repository

type BlacklistedRefreshTokenRepository interface {
	GetByValue(value string) (*BlackListedRefreshToken, error)
	Save(value string) error
}

var inMemoryblackListedTokenDb = make(map[string]string)

type InMemoryBlacklistedRefreshTokenRepository struct {
}

func NewInMemoryBlacklistedRefreshTokenRepository() *InMemoryBlacklistedRefreshTokenRepository {
	return &InMemoryBlacklistedRefreshTokenRepository{}
}

func (r *InMemoryBlacklistedRefreshTokenRepository) GetByValue(value string) (*BlackListedRefreshToken, error) {
	tokenValue, ok := inMemoryblackListedTokenDb[value]
	if !ok {
		return &BlackListedRefreshToken{}, &NotFoundError{}
	}

	return &BlackListedRefreshToken{
		Id:    tokenValue,
		Value: tokenValue,
	}, nil
}

func (r *InMemoryBlacklistedRefreshTokenRepository) Save(value string) error {
	inMemoryblackListedTokenDb[value] = value
	return nil
}

type BlackListedRefreshToken struct {
	Id    string
	Value string
}

// TODO: put this error type in shared place as it is shared by user too
type NotFoundError struct {
}

func (e *NotFoundError) Error() string {
	return "not found in db"
}
