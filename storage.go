package main

import (
	"errors"
	"sync"
)

var (
	ErrNotFound = errors.New("storage: no user found")
)

// storage is a simple in-memory database
type storage struct {
	mu   *sync.Mutex
	data map[string]*user
}

type user struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *storage) Add(data *user) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[data.Username] = data
}

func (s *storage) Find(username string) (*user, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user := s.data[username]
	if user == nil {
		return nil, ErrNotFound
	}

	return user, nil
}

func newStorage() *storage {
	mu := new(sync.Mutex)
	data := make(map[string]*user)

	return &storage{mu, data}
}
