// tls.go

package gxmpp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"errors"
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
	if t.session.tlsFeatureSuccess || !t.srvCfg.UseTls { return nil }
	var buffer bytes.Buffer
	buffer.WriteString("<stream:features>")
	buffer.WriteString("<starttls xmlns='" + xmppNsTLS + "'><required/></starttls>")
	buffer.WriteString("<mechanisms xmlns='" + xmppNsSASL + "'>")
	for i := 0; i< len(saslSupportedMechanisms); i++ {
		buffer.WriteString("<mechanism>" + saslSupportedMechanisms[i] + "</mechanism>")
	}
	buffer.WriteString("</mechanisms>")
	buffer.WriteString("</stream:features>")

	_, err := fmt.Fprint(t.session.w, buffer.String()) // support mechanisms needed
	_, ele, err := next(t.session.dec)
	if err != nil {
		log.Println(err)
		return err
	}

	var ok bool
	_, ok = ele.(*tlsStartTLS)
	if !ok {
		err = errors.New("Expected <starttls>, closing stream")
		log.Println(err)
		fmt.Fprint(t.session.w, "<failure xmlns='" + xmppNsTLS + "'/>" + xmppStreamEnd)
		return err
	}
	fmt.Fprint(t.session.w, "<proceed xmlns='" + xmppNsTLS  + "'/>")
	return t.starttls()
}

func (t *Tls)starttls() error {
	cer, err := tls.LoadX509KeyPair(t.srvCfg.TlsCertFile, t.srvCfg.TlsKeyFile)

	if err !=  nil {
		log.Println(err)
		return err
	}

	tlscfg := &tls.Config{Certificates: []tls.Certificate{cer}}
	// BUGBUG: net.Conn is interface, reference type, suppose any data transformation from here is using new conn, tls
	// tls negotiation
	tlsconn := tls.Server(t.session.conn, tlscfg)
	t.session.setConn(tlsconn)
	err = t.session.talkingInitStream()
	if err != nil {
		log.Println(err)
		return err
	} else {
		t.session.tlsFeatureSuccess = true
	}

	return nil
}
