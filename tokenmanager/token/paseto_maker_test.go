package token

import (
	"Third-Party-Multi-Factor-Authentication-System/util"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPasetoMaker(t *testing.T) {
	maker, err := NewPasetoMaker(util.RandomString(32, util.ALL))
	require.NoError(t, err)
	require.NotEmpty(t, maker)

	username := util.RandomUsername()
	duration := 1 * time.Minute

	issuedAt := time.Now()
	expiredAt := issuedAt.Add(duration)

	token, payload, err := maker.CreateToken(username, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	returnedPayload, err := maker.VerifyToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, returnedPayload)

	require.Equal(t, username, returnedPayload.Username)
	require.NotZero(t, returnedPayload.ID)
	require.WithinDuration(t, issuedAt, returnedPayload.IssuedAt, time.Second)
	require.WithinDuration(t, expiredAt, returnedPayload.ExpiredAt, time.Second)
}

func TestExpiredPasetoToken(t *testing.T) {
	maker, err := NewPasetoMaker(util.RandomString(32, util.ALL))
	require.NoError(t, err)
	require.NotEmpty(t, maker)

	username := util.RandomUsername()
	duration := -time.Minute

	token, payload, err := maker.CreateToken(username, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotEmpty(t, payload)

	returnedPayload, err := maker.VerifyToken(token)
	require.Error(t, err)
	require.Equal(t, err, ErrExpiredToken)
	require.Nil(t, returnedPayload)
}

func TestInvalidPasetoToken(t *testing.T) {
	username := util.RandomUsername()
	duration := time.Minute

	payload, err := NewPayload(username, duration)
	require.NoError(t, err)

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	require.NotEmpty(t, jwtToken)

	// a jwt token is an invalid paseto token
	invalidToken, err := jwtToken.SignedString([]byte(util.RandomString(32, util.ALL)))
	require.NoError(t, err)
	require.NotEmpty(t, invalidToken)

	maker, err := NewPasetoMaker(util.RandomString(32, util.ALL))
	require.NoError(t, err)
	require.NotEmpty(t, maker)

	// a jwt token is an invalid paseto token, so it must return an error
	payload, err = maker.VerifyToken(invalidToken)
	require.Error(t, err)
	require.Equal(t, ErrInvalidToken, err)
	require.Nil(t, payload)
}
