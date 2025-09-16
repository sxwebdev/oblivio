package tpm

import (
	"errors"
	"sync"
)

// NV provides a minimal interface for a TPM2 NV counter.
// This MVP uses an in-memory stub; integrate go-tpm for real TPM usage later.
type NV struct {
	mu  sync.Mutex
	val uint64
}

func NewNV() *NV { return &NV{} }

func (n *NV) Read() (uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.val, nil
}

func (n *NV) Incr() (uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.val == ^uint64(0) {
		return 0, errors.New("counter overflow")
	}
	n.val++
	return n.val, nil
}
