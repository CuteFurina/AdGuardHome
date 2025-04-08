package aghuser

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"go.etcd.io/bbolt"
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
	// Token is the session token.
	Token SessionToken

	// UserID is the identifier of the web user associated with the session.
	UserID UserID

	// UserLogin is the login of the web user associated with the session.
	UserLogin Login

	// Expire indicates when the session will expire.
	Expire time.Time
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

// SessionStorage is an interface that defines methods for handling web user
// sessions.
//
// TODO(s.chzhen):  Add DeleteAll method.
//
// TODO(s.chzhen):  Consider adding Close method.
type SessionStorage interface {
	// New creates a new session for the web user.
	New(ctx context.Context, u *User) (s *Session, err error)

	// Find returns the stored session for the web user based on the session
	// token.
	//
	// TODO(s.chzhen):  Consider function signature change to reflect the
	// in-memory implementation, as it currently always returns nil for error.
	Find(ctx context.Context, t SessionToken) (s *Session, err error)
}

// DefaultSessionStorage is the default bbolt implementation of the
// [SessionStorage] interface.  All methods must be safe for concurrent use.
type DefaultSessionStorage struct {
	// logger is used for logging the operation of the session storage.
	logger *slog.Logger

	// mu protects all properties below.
	mu *sync.Mutex

	// db represents an instance of bbolt.DB.
	db *bbolt.DB

	// sessions maps a session token to a web user session.
	sessions map[SessionToken]*Session

	// sessionTTL is the default Time-To-Live value for web user sessions.
	sessionTTL time.Duration
}

// NewDefaultSessionStorage returns the new properly initialized
// *DefaultSessionStorage.  logger must not be nil.
//
// TODO(s.chzhen):  Consider accepting configuration structure.
func NewDefaultSessionStorage(
	ctx context.Context,
	logger *slog.Logger,
	dbFilename string,
	sessionTTL time.Duration,
) (ds *DefaultSessionStorage, err error) {
	ds = &DefaultSessionStorage{
		logger:     logger,
		mu:         &sync.Mutex{},
		sessions:   map[SessionToken]*Session{},
		sessionTTL: sessionTTL,
	}

	ds.db, err = bbolt.Open(dbFilename, aghos.DefaultPermFile, nil)
	if err != nil {
		ds.logger.ErrorContext(ctx, "opening db %q: %w", dbFilename, err)
		if err.Error() == "invalid argument" {
			// TODO(s.chzhen):  Consider using [slog.Logger].
			log.Error("AdGuard Home cannot be initialized due to an incompatible file system.\nPlease read the explanation here: https://github.com/AdguardTeam/AdGuardHome/wiki/Getting-Started#limitations")
		}

		return nil, err
	}

	err = ds.loadSessions(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading sessions: %w", err)
	}

	return ds, nil
}

// bucketNameSessions is the name of the bucket storing web user sessions in
// bbolt.
const bucketNameSessions = "sessions-2"

// loadSessions loads web user sessions from bbolt.
func (ds *DefaultSessionStorage) loadSessions(ctx context.Context) (err error) {
	tx, err := ds.db.Begin(true)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}

	IsCommitted := false
	defer func() {
		if IsCommitted {
			return
		}

		err = errors.Join(err, tx.Rollback())
	}()

	bkt := tx.Bucket([]byte(bucketNameSessions))
	if bkt == nil {
		return nil
	}

	removed := 0
	now := time.Now()
	err = bkt.ForEach(func(k, v []byte) error {
		s := &Session{}
		if s.deserialize(v) && s.Expire.After(now) {
			t := SessionToken(k)
			ds.sessions[t] = s

			return nil
		}

		err = bkt.Delete(k)
		if err != nil {
			return fmt.Errorf("deleting expired session: %w", err)
		}

		removed++

		return nil
	})
	if err != nil {
		return fmt.Errorf("iterating over sessions: %w", err)
	}

	if removed == 0 {
		return nil
	}

	IsCommitted = true
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	ds.logger.DebugContext(
		ctx,
		"loading sessions from db",
		"stored", len(ds.sessions),
		"removed", removed,
	)

	return nil
}

// type check
var _ SessionStorage = (*DefaultSessionStorage)(nil)

// New implements [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) New(ctx context.Context, u *User) (s *Session, err error) {
	s = &Session{
		Token:     NewSessionToken(),
		UserID:    u.ID,
		UserLogin: u.Login,
		Expire:    time.Now().Add(ds.sessionTTL),
	}

	err = ds.store(s)
	if err != nil {
		return nil, fmt.Errorf("storing session: %w", err)
	}

	return s, nil
}

// store saves a web user session in bbolt.
//
// TODO(s.chzhen): !! Add remove session method.
func (ds *DefaultSessionStorage) store(s *Session) (err error) {
	tx, err := ds.db.Begin(true)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}

	IsCommitted := false
	defer func() {
		if IsCommitted {
			return
		}

		err = errors.Join(err, tx.Rollback())
	}()

	bkt, err := tx.CreateBucketIfNotExists([]byte(bucketNameSessions))
	if err != nil {
		return fmt.Errorf("creating bucket: %w", err)
	}

	err = bkt.Put(s.Token[:], s.serialize())
	if err != nil {
		return fmt.Errorf("putting data: %w", err)
	}

	IsCommitted = true
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// Find implements [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) Find(ctx context.Context, t SessionToken) (s *Session, err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	s, ok := ds.sessions[t]
	if ok {
		return s, nil
	}

	return nil, nil
}

// Close terminates the connection to the web user sessions database.
func (ds *DefaultSessionStorage) Close() (err error) {
	err = ds.db.Close()
	if err != nil {
		return fmt.Errorf("closing db: %w", err)
	}

	return nil
}
