package main

import "sync"

// bufferPool implements httputil.BufferPool to reuse copy buffers across
// requests and cut allocation pressure.
type bufferPool struct{ p sync.Pool }

func newBufferPool() *bufferPool {
	return &bufferPool{p: sync.Pool{New: func() any {
		b := make([]byte, 32*1024)
		return &b
	}}}
}

func (bp *bufferPool) Get() []byte  { return *bp.p.Get().(*[]byte) }
func (bp *bufferPool) Put(b []byte) { bp.p.Put(&b) }
