package internal

import "strings"

type Validator interface {
	ValidUsernamePassword(username, password string) bool
}

type MemoryValidator struct {
	m map[string]string
}

func NewMemoryValidator(users map[string]string) *MemoryValidator {
	return &MemoryValidator{m: users}
}

func ParseUserPasswords(s string) map[string]string {
	users := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		username, password, ok := strings.Cut(pair, ":")
		if !ok {
			continue
		}
		users[strings.TrimSpace(username)] = strings.TrimSpace(password)
	}
	return users
}

func (n *MemoryValidator) ValidUsernamePassword(username string, password string) bool {
	v, ok := n.m[username]
	return ok && v == password
}
