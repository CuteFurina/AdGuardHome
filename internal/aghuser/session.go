package aghuser

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// SessionToken is the type for the web user session token.
type SessionToken [16]byte

// NewSessionToken returns a cryptographically secure randomly generated web
// user session token.  If an error occurs during random generation, it will
// cause the program to crash.
func NewSessionToken() (t SessionToken) {
	_, _ = rand.Read(t[:])

	return t
}

// Session represents a web user session.
type Session struct {
	// Expire indicates when the session will expire.
	Expire time.Time

	// UserLogin is the login of the web user associated with the session.
	UserLogin Login

	// Token is the session token.
	Token SessionToken

	// UserID is the identifier of the web user associated with the session.
	UserID UserID
}

const (
	// sessionExpireLen is the length of the expire field in the binary entry
	// stored in bbolt.
	sessionExpireLen = 4

	// sessionNameLen is the length of the name field in the binary entry stored
	// in bbolt.
	sessionNameLen = 2
)

// serialize encodes a session properties into a binary data.
func (s *Session) serialize() (data []byte) {
	data = make([]byte, sessionExpireLen+sessionNameLen+len(s.UserLogin))

	expireData := data[:sessionExpireLen]
	nameLenData := data[sessionExpireLen : sessionExpireLen+sessionNameLen]
	nameData := data[sessionExpireLen+sessionNameLen:]

	expire := uint32(s.Expire.Unix())
	binary.BigEndian.PutUint32(expireData, expire)
	binary.BigEndian.PutUint16(nameLenData, uint16(len(s.UserLogin)))
	copy(nameData, []byte(s.UserLogin))

	return data
}

// deserialize decodes a binary data into a session properties.
func (s *Session) deserialize(data []byte) (ok bool) {
	if len(data) < sessionExpireLen+sessionNameLen {
		return false
	}

	expireData := data[:sessionExpireLen]
	nameLenData := data[sessionExpireLen : sessionExpireLen+sessionNameLen]
	nameData := data[sessionExpireLen+sessionNameLen:]

	nameLen := binary.BigEndian.Uint16(nameLenData)
	if len(nameData) < int(nameLen) {
		return false
	}

	expire := binary.BigEndian.Uint32(expireData)
	s.Expire = time.Unix(int64(expire), 0)
	s.UserLogin = Login(nameData)

	return true
}
