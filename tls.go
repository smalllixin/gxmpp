// tls.go

package gxmpp

import (
	"fmt"
)

type Tls struct {
	session *Session
	srvCfg *ServerConfig
}

func NewTls(session *Session) *Tls {
	t := &Tls{session: session, srvCfg: session.srv.cfg }
	return t
}

func (tls *Tls)talking() error {
	if tls.srvCfg.tlsFeatureSuccess || !tls.srvCfg.UseTls { return nil }
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
	starttlsnego()
}

func (tls *Tls)starttlsnego() error {

}
