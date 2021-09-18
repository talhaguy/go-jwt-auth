package repository

type BlacklistedRefreshTokenRepository interface {
	GetByValue(value string) (*BlackListedRefreshToken, error)
	Save(value string) error
}

var blackListedTokenDb = make(map[string]string)

type DefaultBlacklistedRefreshTokenRepository struct {
}

func NewDefaultBlacklistedRefreshTokenRepository() *DefaultBlacklistedRefreshTokenRepository {
	return &DefaultBlacklistedRefreshTokenRepository{}
}

func (b *DefaultBlacklistedRefreshTokenRepository) GetByValue(value string) (*BlackListedRefreshToken, error) {
	tokenValue, ok := blackListedTokenDb[value]
	if !ok {
		return &BlackListedRefreshToken{}, &NotFoundError{}
	}

	return &BlackListedRefreshToken{
		Id:    tokenValue,
		Value: tokenValue,
	}, nil
}

func (b *DefaultBlacklistedRefreshTokenRepository) Save(value string) error {
	blackListedTokenDb[value] = value
	return nil
}

type BlackListedRefreshToken struct {
	Id    string
	Value string
}

type NotFoundError struct {
}

func (e *NotFoundError) Error() string {
	return "not found"
}
