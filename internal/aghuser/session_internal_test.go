package aghuser

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

// testTimeout is the common timeout for tests.
//
// TODO(s.chzhen):  Reuse.
const testTimeout = 1 * time.Second

func TestDefaultSessionStorage(t *testing.T) {
	const userLogin Login = "user_login"

	var (
		ctx        = testutil.ContextWithTimeout(t, testTimeout)
		logger     = slogutil.NewDiscardLogger()
		sessionTTL = time.Minute
	)

	// Prepare the database file with session data.

	dbFile, err := os.CreateTemp(t.TempDir(), "sessions.db")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dbFile.Close)

	db, err := bbolt.Open(dbFile.Name(), aghos.DefaultPermFile, nil)
	require.NoError(t, err)

	ds := &DefaultSessionStorage{
		logger:     logger,
		mu:         &sync.Mutex{},
		db:         db,
		sessions:   map[SessionToken]*Session{},
		sessionTTL: sessionTTL,
	}

	session, err := ds.New(ctx, &User{
		ID:    MustNewUserID(),
		Login: userLogin,
	})
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.Equal(t, userLogin, session.UserLogin)

	token := session.Token

	err = ds.Close()
	require.NoError(t, err)

	// Initialize session storage, then assert loaded sessions.

	ds, err = NewDefaultSessionStorage(ctx, logger, dbFile.Name(), sessionTTL)
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, ds.Close)

	got, err := ds.Find(ctx, token)
	require.NoError(t, err)

	assert.Equal(t, userLogin, got.UserLogin)
}
