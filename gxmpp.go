package gxmpp

import (
	"log"
)

func Start(cfg *ServerConfig) (*Server, error) {
	log.Println("Start *gxmpp* Server\n")
	initDefaultConfig()
	if cfg == nil {
		cfg = defaultConfig() 
	}
	s := NewServer(cfg)
	err := s.Start()
	return s, err
}

func Stop(s *Server) {
	s.Stop()
}