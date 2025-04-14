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
	clock := &faketime.Clock{
		OnNow: func() (now time.Time) {
			date = date.Add(time.Second)

			return date
		},
	}

	dbFile, err := os.CreateTemp(t.TempDir(), "sessions.db")
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, dbFile.Close)

	userDB := aghuser.NewDefaultDB()

	err = userDB.Create(ctx, &aghuser.User{
		Login: userLoginFirst,
		ID:    aghuser.MustNewUserID(),
	})
	require.NoError(t, err)

	err = userDB.Create(ctx, &aghuser.User{
		Login: userLoginSecond,
		ID:    aghuser.MustNewUserID(),
	})
	require.NoError(t, err)

	var (
		ds *aghuser.DefaultSessionStorage

		sessionFirst  *aghuser.Session
		sessionSecond *aghuser.Session
	)

	defer func() {
		require.NotNil(t, ds)

		assert.NoError(t, ds.Close())
	}()

	require.True(t, t.Run("prepare_session_storage", func(t *testing.T) {
		ds, err = aghuser.NewDefaultSessionStorage(ctx, &aghuser.DefaultSessionStorageConfig{
			Clock:      clock,
			UserDB:     userDB,
			Logger:     logger,
			DBPath:     dbFile.Name(),
			SessionTTL: sessionTTL,
		})
		require.NoError(t, err)

		sessionFirst, err = ds.New(ctx, &aghuser.User{
			ID:    aghuser.MustNewUserID(),
			Login: userLoginFirst,
		})
		require.NoError(t, err)
		require.NotNil(t, sessionFirst)

		assert.Equal(t, userLoginFirst, sessionFirst.UserLogin)

		// Advance time to ensure the first session expires before creating the
		// second session.
		date = date.Add(time.Hour)

		sessionSecond, err = ds.New(ctx, &aghuser.User{
			ID:    aghuser.MustNewUserID(),
			Login: userLoginSecond,
		})
		require.NoError(t, err)
		require.NotNil(t, sessionSecond)

		assert.Equal(t, userLoginSecond, sessionSecond.UserLogin)

		err = ds.Close()
		require.NoError(t, err)
	}))

	require.True(t, t.Run("load_sessions", func(t *testing.T) {
		ds, err = aghuser.NewDefaultSessionStorage(ctx, &aghuser.DefaultSessionStorageConfig{
			Clock:      clock,
			UserDB:     userDB,
			Logger:     logger,
			DBPath:     dbFile.Name(),
			SessionTTL: sessionTTL,
		})
		require.NoError(t, err)

		var got *aghuser.Session
		got, err = ds.FindByToken(ctx, sessionFirst.Token)
		require.NoError(t, err)

		assert.Nil(t, got)

		got, err = ds.FindByToken(ctx, sessionSecond.Token)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, userLoginSecond, got.UserLogin)

		err = ds.DeleteByToken(ctx, sessionSecond.Token)
		require.NoError(t, err)

		got, err = ds.FindByToken(ctx, sessionSecond.Token)
		require.NoError(t, err)

		assert.Nil(t, got)
	}))

	require.True(t, t.Run("expired_session", func(t *testing.T) {
		// TODO(s.chzhen): !! Add a helper.
		sessionFirst, err = ds.New(ctx, &aghuser.User{
			ID:    aghuser.MustNewUserID(),
			Login: userLoginFirst,
		})
		require.NoError(t, err)
		require.NotNil(t, sessionFirst)

		var got *aghuser.Session
		got, err = ds.FindByToken(ctx, sessionFirst.Token)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, userLoginFirst, got.UserLogin)

		date = date.Add(time.Hour)

		got, err = ds.FindByToken(ctx, sessionFirst.Token)
		require.NoError(t, err)

		assert.Nil(t, got)
	}))
}
