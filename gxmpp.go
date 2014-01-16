package gxmpp

import (
	"log"
)

func Start(cfg *ServerConfig) (*Server, error) {
	log.Println("Start *gxmpp* Server\n")
	if cfg == nil {
		cfg = DefaultConfig() 
	}
	s := NewServer(cfg)
	err := s.Start()
	return s, err
}

func Stop(s *Server) {
	s.Stop()
}