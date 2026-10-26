// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
)

// TunnelErrorFunc is called when a tunnel cannot reach the upstream.
type TunnelErrorFunc func(c net.Conn, err error)

// Tunnel returns a function passing a whole client connection to target
// unmodified: head (bytes already read from c) is replayed, then bytes are
// copied both ways until either side closes. It owns and closes c.
//
// For an https target, the upstream's TLS uses the client's SNI, as in New;
// without one the connection is dropped.
func Tunnel(target *url.URL, onError TunnelErrorFunc) func(c net.Conn, head []byte) {
	addr := addrOf(target)
	return tunnel(onError, func(c net.Conn) (net.Conn, error) { return dialTunnel(c, target, addr) })
}

// RawTunnel is Tunnel without TLS to the upstream, for connections passed
// on still encrypted.
func RawTunnel(target *url.URL, onError TunnelErrorFunc) func(c net.Conn, head []byte) {
	addr := addrOf(target)
	return tunnel(onError, func(net.Conn) (net.Conn, error) { return dialer.Dial("tcp", addr) })
}

func tunnel(onError TunnelErrorFunc, dial func(c net.Conn) (net.Conn, error)) func(c net.Conn, head []byte) {
	return func(c net.Conn, head []byte) {
		defer c.Close()
		up, err := dial(c)
		if err != nil {
			if onError != nil {
				onError(c, err)
			}
			return
		}
		defer up.Close()
		if _, err := up.Write(head); err != nil {
			return
		}
		done := make(chan struct{}, 2)
		go func() {
			io.Copy(up, c)
			closeWrite(up)
			done <- struct{}{}
		}()
		go func() {
			io.Copy(c, up)
			closeWrite(c)
			done <- struct{}{}
		}()
		<-done
		<-done
	}
}

func dialTunnel(c net.Conn, target *url.URL, addr string) (net.Conn, error) {
	up, err := dialer.Dial("tcp", addr)
	if err != nil || target.Scheme != "https" {
		return up, err
	}
	name := ""
	if tc, ok := c.(*tls.Conn); ok {
		name = tc.ConnectionState().ServerName
	}
	if name == "" {
		up.Close()
		return nil, errNoServerName
	}
	tc := tls.Client(up, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
	ctx, cancel := context.WithTimeout(context.Background(), dialer.Timeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		up.Close()
		return nil, err
	}
	return tc, nil
}

var errNoServerName = errors.New("client sent no SNI for the upstream TLS name")

// closeWrite half-closes c if it can, so the peer sees EOF while replies
// still flow back.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
