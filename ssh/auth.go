package c2ssh

import (
	"bytes"
	"errors"
	"net"

	"golang.org/x/crypto/ssh"
)

// The Auth struct stores all the functions utilized for key adding, removing,
// listing, and checking. When a user needs to allow anonymous authentication
// then that is stored directly in this function.
type Auth struct {
	trusted    []ssh.PublicKey
	anonymous  bool
	AddFunc    func(key ssh.PublicKey) error
	RemoveFunc func(key ssh.PublicKey) error
	ListFunc   func() ([]ssh.PublicKey, error)
	CheckFunc  func(addr net.Addr, key ssh.PublicKey) (bool, error)
}

// NewAuth creates a new empty Auth. By default in sauth this function creates
// a simple in memory version of sauth that does not have a set trusted key nor
// allows for anonymous authentication. The NewAuth function will return an
// Auth struct that can then be overridden by the library user or even at
// runtime for situations such as emergency maintanance.
func NewAuth() *Auth {
	a := &Auth{
		trusted:   nil,
		anonymous: false,
	}
	(*a).AddFunc = (*a).addKey
	(*a).RemoveFunc = (*a).removeKey
	(*a).ListFunc = (*a).keys
	(*a).CheckFunc = (*a).check
	return a
}

// Adds a key that is authorized
func (a *Auth) AddKey(key ssh.PublicKey) error {
	return a.AddFunc(key)
}

// By default a new Auth struct AddKey will just use an in memory list of trusted keys
func (a *Auth) addKey(key ssh.PublicKey) error {
	a.trusted = append(a.trusted, key)
	return nil
}

// Removes authorized trusted keys
func (a *Auth) RemoveKey(key ssh.PublicKey) error {
	return a.RemoveFunc(key)
}

// Default Auth structs simply remove a trusted key from the in memory store
func (a *Auth) removeKey(delKey ssh.PublicKey) error {
	for index, key := range a.trusted {
		if key == delKey {
			a.trusted = append(a.trusted[:index], a.trusted[index+1:]...)
			return nil
		}
	}
	return errors.New("Key not found")
}

// List trusted keys
func (a *Auth) Keys() ([]ssh.PublicKey, error) {
	return a.ListFunc()
}

// Default auth returns the memory stored trusted keys
func (a *Auth) keys() ([]ssh.PublicKey, error) {
	return a.trusted, nil
}

// AllowAnonymous sets whether keys that aren't in the trusted list are allowed
// to reach the post authentication phase and handlers.
func (a *Auth) AllowAnonymous(anon bool) bool {
	a.anonymous = anon
	return a.anonymous
}

// Check if anonymous authentication is allowed
func (a *Auth) Anonymous() bool {
	return a.anonymous
}

// Check whether or not a public key is allowed. This function also accepts
// some metadata besides just keys, like IP addresses that are exposed for any
// application firewalling or other checks
func (a *Auth) Check(addr net.Addr, key ssh.PublicKey) (bool, error) {
	return a.check(addr, key)
}

// Check determines if a pubkey fingerprint is permitted, in the default mode
// just checks if a key is in the trusted list
func (a *Auth) check(addr net.Addr, key ssh.PublicKey) (bool, error) {
	if len(a.trusted) < 1 {
		return false, errors.New("No trusted keys")
	}
	for _, trustedKey := range a.trusted {
		if bytes.Equal(key.Marshal(), trustedKey.Marshal()) {
			return true, nil
		}
	}
	return false, nil
}
