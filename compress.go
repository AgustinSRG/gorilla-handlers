// Copyright 2013 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package handlers

import (
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/felixge/httpsnoop"
)

const acceptEncoding string = "Accept-Encoding"

type compressResponseWriter struct {
	compressor io.Writer
	w          http.ResponseWriter
	encoding   string
}

func (cw *compressResponseWriter) WriteHeader(c int) {
	h := cw.w.Header()

	// Go 1.23 introduced a breaking change makes it so Content-Encoding is deleted under certain conditions
	// For example if an error floats out of ServeContent (https://pkg.go.dev/net/http@master#ServeContent)
	// See also:
	//		https://github.com/golang/go/issues/66343
	// 		https://github.com/golang/go/issues/71149
	// 		https://tip.golang.org/doc/go1.23#language
	//
	// If Content-Encoding is missing, add it back in
	if h.Get("Content-Encoding") == "" {
		h.Set("Content-Encoding", cw.encoding)
	}

	cw.w.Header().Del("Content-Length")
	cw.w.WriteHeader(c)
}

func (cw *compressResponseWriter) Write(b []byte) (int, error) {
	h := cw.w.Header()

	// If Content-Encoding is missing, return an uncompressed response
	// This can happen starting with Go 1.23 if an error floats out of ServeContent(https://pkg.go.dev/net/http@master#ServeContent)
	if h.Get("Content-Encoding") == "" {
		return cw.w.Write(b)
	}

	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", http.DetectContentType(b))
	}

	h.Del("Content-Length")

	return cw.compressor.Write(b)
}

func (cw *compressResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(cw.compressor, r)
}

type flusher interface {
	Flush() error
}

func (cw *compressResponseWriter) Flush() {
	// Flush compressed data if compressor supports it.
	if f, ok := cw.compressor.(flusher); ok {
		_ = f.Flush()
	}
	// Flush HTTP response.
	if f, ok := cw.w.(http.Flusher); ok {
		f.Flush()
	}
}

// CompressHandler gzip compresses HTTP responses for clients that support it
// via the 'Accept-Encoding' header.
//
// Compressing TLS traffic may leak the page contents to an attacker if the
// page contains user input: http://security.stackexchange.com/a/102015/12208
func CompressHandler(h http.Handler) http.Handler {
	return CompressHandlerLevel(h, gzip.DefaultCompression)
}

// CompressHandlerLevel gzip compresses HTTP responses with specified compression level
// for clients that support it via the 'Accept-Encoding' header.
//
// The compression level should be gzip.DefaultCompression, gzip.NoCompression,
// or any integer value between gzip.BestSpeed and gzip.BestCompression inclusive.
// gzip.DefaultCompression is used in case of invalid compression level.
func CompressHandlerLevel(h http.Handler, level int) http.Handler {
	if level < gzip.DefaultCompression || level > gzip.BestCompression {
		level = gzip.DefaultCompression
	}

	const (
		gzipEncoding  = "gzip"
		flateEncoding = "deflate"
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// detect what encoding to use
		var encoding string
		for _, curEnc := range strings.Split(r.Header.Get(acceptEncoding), ",") {
			curEnc = strings.TrimSpace(curEnc)
			if curEnc == gzipEncoding || curEnc == flateEncoding {
				encoding = curEnc
				break
			}
		}

		// always add Accept-Encoding to Vary to prevent intermediate caches corruption
		w.Header().Add("Vary", acceptEncoding)

		// if we weren't able to identify an encoding we're familiar with, pass on the
		// request to the handler and return
		if encoding == "" {
			h.ServeHTTP(w, r)
			return
		}

		if r.Header.Get("Upgrade") != "" {
			h.ServeHTTP(w, r)
			return
		}

		// wrap the ResponseWriter with the writer for the chosen encoding
		var encWriter io.WriteCloser
		switch encoding {
		case gzipEncoding:
			encWriter, _ = gzip.NewWriterLevel(w, level)
		case flateEncoding:
			encWriter, _ = flate.NewWriter(w, level)
		}
		defer encWriter.Close()

		w.Header().Set("Content-Encoding", encoding)
		r.Header.Del(acceptEncoding)

		cw := &compressResponseWriter{
			w:          w,
			compressor: encWriter,
			encoding:   encoding,
		}

		w = httpsnoop.Wrap(w, httpsnoop.Hooks{
			Write: func(httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return cw.Write
			},
			WriteHeader: func(httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return cw.WriteHeader
			},
			Flush: func(httpsnoop.FlushFunc) httpsnoop.FlushFunc {
				return cw.Flush
			},
			ReadFrom: func(rff httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
				return cw.ReadFrom
			},
		})

		h.ServeHTTP(w, r)
	})
}
