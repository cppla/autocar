package testdata

import (
	"crypto/tls"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCertificates(t *testing.T) {
	ln, err := tls.Listen("tcp", "localhost:0", GetTLSConfig())
	require.NoError(t, err)

	go func() {
		conn, err := ln.Accept()
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte("foobar"))
		require.NoError(t, err)
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		RootCAs:    GetRootCA(),
		ServerName: "localhost",
	})
	require.NoError(t, err)
	data, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, "foobar", string(data))
}
