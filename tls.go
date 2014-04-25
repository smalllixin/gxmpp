// tls.go

package gxmpp

import (
	"crypto/tls"
	"fmt"
	"net"
)

type Tls struct {
	session *Session
	srvCfg *ServerConfig
}

func NewTls(session *Session) *Tls {
	t := &Tls{session: session, srvCfg: session.srv.cfg }
	return t
}

func (t *Tls)talking() error {
	if t.srvCfg.tlsFeatureSuccess || !t.srvCfg.UseTls { return nil }
	_, err := fmt.Fprint(s.session.w, "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'></required/></starttls></stream:features>") // support mechanisms needed
	_, ele, err := next(s.session.dec)
	if err != nil {
		log.Println(err)
		return err
	}

	var ok bool
	var stls *tlsStartTLS
	stls, ok = ele.(*tlsStartTLS)
	if !ok {
		err = errors.New("Expected <starttls>, closing stream")
		log.Println(err)
		fmt.Fprint(s.session.w, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>")
		return err
	}

	fmt.Fprint(s.session.w, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
	starttls()
}

func (t *Tls)starttls() error {
	cer, err := tls.LoadX509KeyPair(tls.srvCfg.TlsCertFile, tls.srvCfg.TlsKeyFile)

	if err !=  nil {
		log.Println(err)
		return err
	}

	tlscfg := &tls.Config{Certificates: []tls.Certificate{cer}}
	// BUGBUG: net.Conn is interface, reference type, suppose any data transformation from here is using new conn, tls
	// tls negotiation
	t.session.conn = tls.Server(t.session.conn, tlscfg)
}
