package aghuser

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// SessionStorage is an interface that defines methods for handling web user
// sessions.
//
// TODO(s.chzhen):  Add DeleteAll method.
type SessionStorage interface {
	// New creates a new session for the web user.
	New(ctx context.Context, u *User) (s *Session, err error)

	// FindByToken returns the stored session for the web user based on the session
	// token.
	//
	// TODO(s.chzhen):  Consider function signature change to reflect the
	// in-memory implementation, as it currently always returns nil for error.
	FindByToken(ctx context.Context, t SessionToken) (s *Session, err error)

	// DeleteByToken removes a stored web user session by the provided token.
	DeleteByToken(ctx context.Context, t SessionToken) (err error)

	// Close releases the web user sessions database resources.
	Close() (err error)
}

// DefaultSessionStorageConfig represents the web user session storage
// configuration structure.
type DefaultSessionStorageConfig struct {
	// Clock is used to get the current time.  It must not be nil.
	Clock timeutil.Clock

	// Logger is used for logging the operation of the session storage.  It must
	// not be nil.
	Logger *slog.Logger

	// DBFilename is the path to the database file where session data is stored.
	// It must not be empty.
	DBFilename string

	// SessionTTL is the default Time-To-Live duration for web user sessions.
	// It specifies how long a session should last and is a required field.
	SessionTTL time.Duration
}

// DefaultSessionStorage is the default bbolt database implementation of the
// [SessionStorage] interface.  All methods must be safe for concurrent use.
type DefaultSessionStorage struct {
	// clock is used to get the current time.
	clock timeutil.Clock

	// logger is used for logging the operation of the session storage.
	logger *slog.Logger

	// db is an instance of the bbolt database where web user sessions are
	// stored by [SessionToken] in the [bucketNameSessions] bucket.
	db *bbolt.DB

	// mu protects sessions.
	mu *sync.Mutex

	// sessions maps a session token to a web user session.
	sessions map[SessionToken]*Session

	// sessionTTL is the default Time-To-Live value for web user sessions.
	sessionTTL time.Duration
}

// NewDefaultSessionStorage returns the new properly initialized
// *DefaultSessionStorage.
func NewDefaultSessionStorage(
	ctx context.Context,
	conf *DefaultSessionStorageConfig,
) (ds *DefaultSessionStorage, err error) {
	ds = &DefaultSessionStorage{
		clock:      conf.Clock,
		logger:     conf.Logger,
		mu:         &sync.Mutex{},
		sessions:   map[SessionToken]*Session{},
		sessionTTL: conf.SessionTTL,
	}

	dbFilename := conf.DBFilename
	ds.db, err = bbolt.Open(dbFilename, aghos.DefaultPermFile, nil)
	if err != nil {
		ds.logger.ErrorContext(ctx, "opening db %q: %w", dbFilename, err)
		if errors.Is(err, berrors.ErrInvalid) {
			slogutil.PrintLines(ctx, ds.logger, slog.LevelError, "", "AdGuard Home cannot be initialized due to an incompatible file system.\nPlease read the explanation here: https://github.com/AdguardTeam/AdGuardHome/wiki/Getting-Started#limitations")
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
// the bbolt database.
const bucketNameSessions = "sessions-2"

// loadSessions loads web user sessions from the bbolt database.
func (ds *DefaultSessionStorage) loadSessions(ctx context.Context) (err error) {
	tx, err := ds.db.Begin(true)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}

	needRollback := true
	defer func() {
		if !needRollback {
			return
		}

		err = errors.Join(err, tx.Rollback())
	}()

	bkt := tx.Bucket([]byte(bucketNameSessions))
	if bkt == nil {
		return nil
	}

	removed, err := ds.processSessions(bkt)
	if err != nil {
		return fmt.Errorf("processing sessions: %w", err)
	}

	if removed == 0 {
		ds.logger.DebugContext(ctx, "loading sessions from db", "stored", len(ds.sessions))

		return nil
	}

	needRollback = false
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

// processSessions iterates over the sessions bucket and loads or removes
// sessions as needed.
func (ds *DefaultSessionStorage) processSessions(bkt *bbolt.Bucket) (removed int, err error) {
	now := ds.clock.Now()

	err = bkt.ForEach(func(k, v []byte) error {
		s := &Session{}
		if s.deserialize(v) && s.Expire.After(now) {
			ds.sessions[SessionToken(k)] = s

			return nil
		}

		if err = bkt.Delete(k); err != nil {
			return fmt.Errorf("deleting expired session: %w", err)
		}

		removed++

		return nil
	})

	if err != nil {
		// Don't wrap the error because it's informative enough as is.
		return removed, err
	}

	return removed, nil
}

// type check
var _ SessionStorage = (*DefaultSessionStorage)(nil)

// New implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) New(ctx context.Context, u *User) (s *Session, err error) {
	s = &Session{
		Token:     NewSessionToken(),
		UserID:    u.ID,
		UserLogin: u.Login,
		Expire:    ds.clock.Now().Add(ds.sessionTTL),
	}

	err = ds.store(s)
	if err != nil {
		return nil, fmt.Errorf("storing session: %w", err)
	}

	return s, nil
}

// store saves a web user session in the bbolt database.
func (ds *DefaultSessionStorage) store(s *Session) (err error) {
	tx, err := ds.db.Begin(true)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}

	needRollback := true
	defer func() {
		if !needRollback {
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

	needRollback = false
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

// FindByToken implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) FindByToken(ctx context.Context, t SessionToken) (s *Session, err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	s, ok := ds.sessions[t]
	if ok {
		return s, nil
	}

	return nil, nil
}

// DeleteByToken implements the [SessionStorage] interface for
// *DefaultSessionStorage.
func (ds *DefaultSessionStorage) DeleteByToken(ctx context.Context, t SessionToken) (err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	delete(ds.sessions, t)

	err = ds.remove(ctx, t[:])
	if err != nil {
		ds.logger.ErrorContext(ctx, "deleting session", slogutil.KeyError, err)

		return err
	}

	return nil
}

// remove deletes a web user session from the bbolt database.
func (ds *DefaultSessionStorage) remove(ctx context.Context, token []byte) (err error) {
	tx, err := ds.db.Begin(true)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}

	needRollback := true
	defer func() {
		if !needRollback {
			return
		}

		err = errors.Join(err, tx.Rollback())
	}()

	bkt := tx.Bucket([]byte(bucketNameSessions))
	if bkt == nil {
		return errors.Error("no bucket")
	}

	err = bkt.Delete(token)
	if err != nil {
		return fmt.Errorf("removing data: %w", err)
	}

	needRollback = false
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	ds.logger.DebugContext(ctx, "removed session from db")

	return err
}

// Close implements the [SessionStorage] interface for *DefaultSessionStorage.
func (ds *DefaultSessionStorage) Close() (err error) {
	err = ds.db.Close()
	if err != nil {
		return fmt.Errorf("closing db: %w", err)
	}

	return nil
}
