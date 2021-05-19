package gonetmd

import "math/rand"

type Nonce struct {
	Host []byte
	Dev  []byte
}

func NewNonce() (n *Nonce) {
	n = &Nonce{}
	n.Host = make([]byte, 8)
	for i := 0; i < 8; i++ {
		n.Host[i] = byte(rand.Int()) & 0xff
	}
	return
}

func (n *Nonce) Merged() []byte {
	return append(n.Host, n.Dev...)
}
