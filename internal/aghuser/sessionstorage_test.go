package aghuser_test

import (
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghuser"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/faketime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSessionStorage(t *testing.T) {
	const (
		userLoginFirst  aghuser.Login = "user_one"
		userLoginSecond aghuser.Login = "user_two"
	)

	var (
		ctx        = testutil.ContextWithTimeout(t, testTimeout)
		logger     = slogutil.NewDiscardLogger()
		sessionTTL = time.Minute
	)

	// Set up a mock clock to test expired sessions.
	date := time.Now()
	mockClock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			date = date.Add(time.Second)

			return date
		},
	}

	// Prepare the database file with session data.

	dbFile, err := os.CreateTemp(t.TempDir(), "sessions.db")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dbFile.Close)

	ds, err := aghuser.NewDefaultSessionStorage(ctx, &aghuser.DefaultSessionStorageConfig{
		Clock:      mockClock,
		Logger:     logger,
		DBFilename: dbFile.Name(),
		SessionTTL: time.Minute,
	})
	require.NoError(t, err)

	sessionFirst, err := ds.New(ctx, &aghuser.User{
		ID:    aghuser.MustNewUserID(),
		Login: userLoginFirst,
	})
	require.NoError(t, err)
	require.NotNil(t, sessionFirst)

	assert.Equal(t, userLoginFirst, sessionFirst.UserLogin)

	// Advance time to ensure the first session expires before creating the
	// second session.
	date = date.Add(time.Hour)

	sessionSecond, err := ds.New(ctx, &aghuser.User{
		ID:    aghuser.MustNewUserID(),
		Login: userLoginSecond,
	})
	require.NoError(t, err)
	require.NotNil(t, sessionSecond)

	assert.Equal(t, userLoginSecond, sessionSecond.UserLogin)

	err = ds.Close()
	require.NoError(t, err)

	// Initialize session storage, then assert loaded sessions.

	ds, err = aghuser.NewDefaultSessionStorage(ctx, &aghuser.DefaultSessionStorageConfig{
		Clock:      mockClock,
		Logger:     logger,
		DBFilename: dbFile.Name(),
		SessionTTL: sessionTTL,
	})
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, ds.Close)

	got, err := ds.FindByToken(ctx, sessionFirst.Token)
	require.NoError(t, err)

	assert.Nil(t, got)

	got, err = ds.FindByToken(ctx, sessionSecond.Token)
	require.NoError(t, err)

	assert.Equal(t, userLoginSecond, got.UserLogin)

	err = ds.DeleteByToken(ctx, sessionSecond.Token)
	require.NoError(t, err)

	got, err = ds.FindByToken(ctx, sessionSecond.Token)
	require.NoError(t, err)

	assert.Nil(t, got)
}
