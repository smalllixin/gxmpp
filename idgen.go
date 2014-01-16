package gxmpp

import (
	"math/rand"
	"time"
	"encoding/base64"
)

/*
Stream Id Generator
*/
type IdGen interface {
	NextId() string
}

type Base64IdGen struct {
	randSrc rand.Source
}

func NewBase64IdGen() IdGen {
	ig := new(Base64IdGen)
	ig.randSrc = rand.NewSource(time.Now().UnixNano())
	return ig
}

// Read satisfies io.Reader
func (s *Base64IdGen) Read(p []byte) (n int, err error) {
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

func (s *Base64IdGen) NextId() string {
	//sha1(random number + timestamp)
	buf := make([]byte, 8*2, 8*2)
	val := time.Now().UnixNano()
	for i := 0; i < 8; i ++ {
		buf[i] = byte(val)
		val >>= 8
	}
	s.Read(buf[8:])
	return base64.URLEncoding.EncodeToString(buf)
}