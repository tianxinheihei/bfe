// Copyright (c) 2019 Baidu, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package h2c implements the unencrypted "h2c" form of HTTP/2.
//
// The h2c protocol is the non-TLS version of HTTP/2 which is not available from
// net/http or golang.org/x/net/http2.

package bfe_h2c

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

import (
	"github.com/baidu/go-lib/log"
)

import (
	http "github.com/baidu/bfe/bfe_http"
	http2 "github.com/baidu/bfe/bfe_http2"
)

const (
	H2C = "h2c"
)

type Server struct {
	s *http2.Server
}

// bufWriter is a Writer interface that also has a Flush method.
type bufWriter interface {
	io.Writer
	Flush() error
}

// rwConn implements net.Conn but overrides Read and Write so that reads and
// writes are forwarded to the provided io.Reader and bufWriter.
type rwConn struct {
	net.Conn
	io.Reader
	BufWriter bufWriter
}

// Read forwards reads to the underlying Reader.
func (c *rwConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

// Write forwards writes to the underlying bufWriter and immediately flushes.
func (c *rwConn) Write(p []byte) (int, error) {
	n, err := c.BufWriter.Write(p)
	if err := c.BufWriter.Flush(); err != nil {
		return 0, err
	}
	return n, err
}

// initH2CWithPriorKnowledge implements creating a h2c connection with prior
// knowledge (Section 3.4) and creates a net.Conn suitable for http2.ServeConn.
// All we have to do is look for the client preface that is suppose to be part
// of the body, and reforward the client preface on the net.Conn this function
// creates.
func initH2CWithPriorKnowledge(w http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		panic("Hijack not supported.")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		panic(fmt.Sprintf("Hijack failed: %v", err))
	}

	const expectedBody = "SM\r\n\r\n"

	buf := make([]byte, len(expectedBody))
	n, err := io.ReadFull(rw, buf)
	if err != nil {
		return nil, fmt.Errorf("could not read from the buffer: %s", err)
	}

	if string(buf[:n]) == expectedBody {
		c := &rwConn{
			Conn:      conn,
			Reader:    io.MultiReader(strings.NewReader(http2.ClientPreface), rw),
			BufWriter: rw.Writer,
		}
		return c, nil
	}

	conn.Close()
	log.Logger.Error(
		"h2c: missing the request body portion of the client preface. Wanted: %v Got: %v",
		[]byte(expectedBody),
		buf[0:n],
	)
	return nil, errors.New("invalid client preface")
}

func NewProtoHandler(conf *Server) func(*http.Server, http.ResponseWriter, *http.Request, http.Handler) {
	if conf == nil {
		conf = new(Server)
	}

	if conf.s == nil {
		conf.s = new(http2.Server)
	}

	protoHandler := func(hs *http.Server, w http.ResponseWriter, r *http.Request, h http.Handler) {
		c, err := initH2CWithPriorKnowledge(w)
		if err != nil {
			return
		}
		connOpts := &http2.ServeConnOpts{hs, h}
		conf.s.ServeConn(c, connOpts)
	}
	return protoHandler
}

// Handle h2c with prior knowledge (RFC 7540 Section 3.4)
func CheckUpgradeH2(r *http.Request) bool {
	if r.Method == "PRI" && len(r.Header) == 0 && r.URL.Path == "*" && r.Proto == "HTTP/2.0" {
		return true
	}
	return false
}
