package gxmpp

/**
Connection Manager
*/

import (
	"log"
	"net"
	"time"
	"fmt"
)

var _ = fmt.Println

type Server struct {
	cfg *ServerConfig
	quitCh chan byte
	listenAddr *net.TCPAddr
	idg IdGen	//id generator
}

func NewServer(cfg *ServerConfig) *Server {
	return new(Server).init(cfg)
}

func (s *Server)init(cfg *ServerConfig) *Server {
	s.cfg = cfg
	s.quitCh = make(chan byte)
	s.idg = NewBase64IdGen()
	return s
}

func (s *Server) HandleConnection(conn net.Conn) {
	session := NewSession(s, conn)
	session.Talking()
}

func (s *Server) Start() error {
	laddr, err := net.ResolveTCPAddr("tcp", s.cfg.C2SPort)
	if err != nil {
		log.Fatalln(err)
		return err
	}
	s.listenAddr = laddr
	ln, err := net.ListenTCP("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		select {
		case <- s.quitCh:
			log.Println("Receive Quit")
			return nil
		default:
		}
		ln.SetDeadline(time.Now().Add(time.Second*10))	//for the graceful quit
		conn, err := ln.AcceptTCP()
		if err != nil {
			switch e := err.(type) {
			case *net.OpError:
				if e.Timeout() != true {
					log.Fatalln("ln.Accept error:", e)
				}
				continue
			default:
				log.Fatalln("ln.Accept error:", e)
				continue
			}
		}
		go s.HandleConnection(conn)
	}
	return nil
}

func (s *Server) Stop() {
	s.quitCh <- 1
}