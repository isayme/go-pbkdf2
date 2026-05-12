package pbkdf2

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	require := require.New(t)

	t.Run("hash with default params", func(t *testing.T) {
		hashed, err := Hash("123456", DefaultParams)
		require.Nil(err)

		ok, err := Verify("123456", hashed)
		require.Nil(err)
		require.True(ok)

		require.True(strings.Contains(hashed, fmt.Sprintf("i=%d", DefaultParams.Iterations)))
	})

	t.Run("hash with digest", func(t *testing.T) {
		testCases := []string{
			"sha1",
			"sha256",
			"sha512",
		}

		for _, tc := range testCases {
			hashed, err := Hash("123456", Params{Digest: tc, Iterations: 1000, KeyLen: 32})
			require.Nil(err)

			ok, err := Verify("123456", hashed)
			require.Nil(err)
			require.True(ok)

			require.True(strings.HasPrefix(hashed, fmt.Sprintf("$pbkdf2-%s$", tc)))
		}
	})
}

func TestVerify(t *testing.T) {
	require := require.New(t)

	t.Run("verify", func(t *testing.T) {
		testCases := []struct {
			password string
			hashed   string
		}{
			{
				password: "password",
				hashed:   "$pbkdf2-sha256$i=6400$0ZrzXitFSGltTQnBWOsdAw==$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M=",
			},
		}

		for _, tc := range testCases {
			ok, err := Verify(tc.password, tc.hashed)
			require.Nil(err)
			require.True(ok)
		}
	})

	t.Run("error", func(t *testing.T) {
		valid, err := Verify("123", "base hased")
		require.NotNil(err)
		require.False(valid)
	})
}

func TestParseHashed(t *testing.T) {
	require := require.New(t)

	t.Run("parse digest", func(t *testing.T) {
		testCases := []struct {
			hashed string
			digest string
		}{
			{
				hashed: "$pbkdf2-sha1$i=1$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
				digest: "sha1",
			},
			{
				hashed: "$pbkdf2-sha256$i=1$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
				digest: "sha256",
			},
			{
				hashed: "$pbkdf2-sha512$i=1$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
				digest: "sha512",
			},
		}

		for _, tc := range testCases {
			_, _, params, err := parseHashed(tc.hashed)
			require.Nil(err)
			require.Equal(tc.digest, params.Digest)
		}
	})

	t.Run("parse salt", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			expectSalt, err := randomBytes(4)
			require.Nil(err)

			expectKey, err := randomBytes(5)
			require.Nil(err)

			hashed := fmt.Sprintf("$pbkdf2-sha256$i=1$%s$%s", base64.StdEncoding.EncodeToString(expectSalt), base64.StdEncoding.EncodeToString(expectKey))
			key, salt, _, err := parseHashed(hashed)
			require.Nil(err)
			require.Equal(expectSalt, salt)
			require.Equal(expectKey, key)
		}
	})

	t.Run("parse params", func(t *testing.T) {
		testCases := []struct {
			hashed string
			params Params
		}{
			{
				hashed: "$pbkdf2-sha1$i=10000$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
				params: Params{
					Iterations: 10000,
					KeyLen:     32,
				},
			},
		}

		for _, tc := range testCases {
			_, _, params, err := parseHashed(tc.hashed)
			require.Nil(err)
			require.Equal(tc.params.KeyLen, params.KeyLen)
			require.Equal(tc.params.Iterations, params.Iterations)
		}
	})

	t.Run("bad cases", func(t *testing.T) {
		testCases := []string{
			"$pbkdf21$i=1000$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
			"$pbkdf-sha256$i=6400$0ZrzXitFSGltTQnBWOsdAw==$Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M=",
			"$pbkdf2-sha1$i-0$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
			"$pbkdf2-sha1$i=a$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6W+KEK+s0DE=",
			"$pbkdf2-sha1$i=1000$WAQ74Fsr6DjVztxcFc0Kjw$tVLlmbQ8lccl39BGaj4asiqB6W+KEK+s0DE=",
			"$pbkdf2-sha1$i=1000$WAQ74Fsr6DjVztxcFc0Kjw==$tVLlmbQ8lYtI6/VHPccl39BGaj4asiqB6DE",
		}

		for _, tc := range testCases {
			_, _, _, err := parseHashed(tc)
			require.NotNil(err)
		}
	})
}
