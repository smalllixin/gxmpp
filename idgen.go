package gxmpp

import (
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
	randMaker *RandomMaker
}

func NewBase64IdGen() IdGen {
	ig := new(Base64IdGen)
	ig.randMaker = NewRandomMaker()
	return ig
}

func (s *Base64IdGen) NextId() string {
	//sha1(random number + timestamp)
	buf := make([]byte, 8*2, 8*2)
	val := time.Now().UnixNano()
	for i := 0; i < 8; i ++ {
		buf[i] = byte(val)
		val >>= 8
	}
	s.randMaker.Read(buf[8:])
	return base64.URLEncoding.EncodeToString(buf)
}