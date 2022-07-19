package lib

type Token struct {
	Token string
	TokenType string // hash | password
}

type LDAPInfo struct {
	Domain string
	Username string
	Token Token
	IP string
	Port string
}