package core

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

type UserStore interface {
	AddUser(account string, password string) error
	RemoveUser(account string) error
	VerifyAccountPassword(account, password string) error
	// RangeAccounts 遍历所有账户（不含密码），fn 返回 false 时停止。
	RangeAccounts(fn func(account string) bool)
}

type UserStoreMemory struct {
	m sync.Map
}

func NewUserStoreMemory() *UserStoreMemory {
	return &UserStoreMemory{}
}

func (s *UserStoreMemory) AddUser(account, password string) error {
	_, loaded := s.m.LoadOrStore(account, password)
	if loaded {
		return fmt.Errorf("user %s already exists", account)
	}
	return nil
}

func (s *UserStoreMemory) RemoveUser(account string) error {
	_, loaded := s.m.LoadAndDelete(account)
	if !loaded {
		return fmt.Errorf("user %s does not exist", account)
	}
	return nil
}

func (s *UserStoreMemory) VerifyAccountPassword(account, password string) error {
	v, ok := s.m.Load(account)
	if !ok || v.(string) != password {
		return errors.New("invalid account or password")
	}
	return nil
}

func (s *UserStoreMemory) RangeAccounts(fn func(account string) bool) {
	s.m.Range(func(k, _ any) bool {
		return fn(k.(string))
	})
}

// parseAccountPassword 解析 "account:password" 形式的认证凭据。
// account 和 password 均不能为空，格式不合法时返回错误。
func parseAccountPassword(pair string) (account, password string, err error) {
	account, password, ok := strings.Cut(pair, ":")
	account, password = strings.TrimSpace(account), strings.TrimSpace(password)
	if !ok || account == "" || password == "" {
		return "", "", fmt.Errorf("invalid account:password pair %q", pair)
	}
	return account, password, nil
}

// NewUserStoreMemoryWithFile 从数据源文件构建内存账户存储。
// 每行一条 "account:password"，支持 # 注释和空行；格式非法或账户重复均返回错误。
func NewUserStoreMemoryWithFile(path string) (*UserStoreMemory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var us UserStoreMemory
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		account, password, err := parseAccountPassword(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		if err = us.AddUser(account, password); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
	}
	return &us, nil
}
