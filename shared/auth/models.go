package auth

type JWTConfig struct {
	Issuer string
	Secret []byte
}
