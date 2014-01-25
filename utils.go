package gxmpp

import (
	"math/rand"
	"time"
)


type RandomMaker struct {
	randSrc rand.Source
}

func NewRandomMaker() *RandomMaker {
	ig := new(RandomMaker)
	ig.randSrc = rand.NewSource(time.Now().UnixNano())
	return ig
}


// Read satisfies io.Reader
func (s *RandomMaker) Read(p []byte) (n int, err error) {
    todo := len(p)
    offset := 0
    for {
        val := int64(s.randSrc.Int63())
        for i := 0; i < 8; i++ {
                p[offset] = byte(val)
                todo--
                if todo == 0 {
                        return len(p), nil
                }
                offset++
                val >>= 8
        }
    }
}