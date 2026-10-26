// SPDX-License-Identifier: AGPL-3.0-or-later

package proxy

import (
	"bufio"
	"io"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestTunnel(t *testing.T) {
	const header = "CONNECT PageKite:1 HTTP/1.0\r\nX-PageKite: a:b:c\r\n\r\n"
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	gotHeader := make(chan string, 1)
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(header))
		io.ReadFull(c, buf)
		gotHeader <- string(buf)
		io.WriteString(c, "HTTP/1.0 200 OK\r\n\r\n")
		io.Copy(c, c)
	}()

	target, _ := url.Parse("http://" + upLn.Addr().String())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tunnel := Tunnel(target, nil)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		tunnel(c, []byte(header[:10]))
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, header[10:]+"ping")
	if got := <-gotHeader; got != header {
		t.Fatalf("upstream got header %q", got)
	}
	br := bufio.NewReader(c)
	if status, _ := br.ReadString('\n'); status != "HTTP/1.0 200 OK\r\n" {
		t.Fatalf("status %q", status)
	}
	br.ReadString('\n')
	echo := make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo %q, %v", echo, err)
	}
}
