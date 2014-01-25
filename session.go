package gxmpp

import (
	"encoding/xml"
	"log"
	"fmt"
	"net"
	"time"
	"io"
	"os"
	"errors"
	"bytes"
)

var _ = fmt.Println
var _ = errors.New
var _ = bytes.Count


type Session struct {
	conn net.Conn
	w io.Writer 	//to client writer
	srv *Server
	dec *xml.Decoder
	enc *xml.Encoder
	CallinTime int64 //unix timestamp
	tlsFeatureSuccess bool
	saslFeatureSuccess bool
	randMaker *RandomMaker
}

var _randMaker *RandomMaker

func NewSession(srv *Server, conn net.Conn) *Session{
	s := new(Session)
	s.conn = conn
	s.srv = srv
	s.CallinTime = time.Now().Unix()
	if srv.cfg.DebugEnable {
		s.dec = xml.NewDecoder(readTunnel{s.conn, os.Stdout})
		s.w = writeTunnel{s.conn, os.Stdout}
	} else {
		s.dec = xml.NewDecoder(s.conn)
		s.w = s.conn
	}
	s.enc = xml.NewEncoder(s.conn)
	s.tlsFeatureSuccess = false
	s.saslFeatureSuccess = false

	if _randMaker == nil {
		_randMaker = NewRandomMaker()
	}
	s.randMaker = _randMaker
	return s
}

func (s *Session) Talking() {
	defer func() {
		s.conn.Close()
		log.Println("socket closed")
	}()
	//TBD:
	//rfc6120 4.6.  Handling of Silent Peers
	if err := s.talkingInitStream(); err != nil {
		return
	}

	if err := s.talkingFeatures(); err != nil {
		return
	}
}

func (s *Session) talkingFeatures() error {
	/*
	R: <stream:features>
     <starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>
       <required/>
     </starttls>
   </stream:features>

   R: <stream:features>
     <bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>
     <compression xmlns='http://jabber.org/features/compress'>
       <method>zlib</method>
       <method>lzw</method>
     </compression>
   </stream:features>

	R: <stream:features/> //stream negotiation is complete

	If features negotation is not complete,
	any of <message/> <present/> <iq/> elements will cause a <not-authorized/> stream error
	
	For client-to-server communication, both SASL negotiation and resource binding MUST be 
	completed before the server can determine the client's address. 

	TBD features talking loop
	*/
	if !s.tlsFeatureSuccess && s.srv.cfg.UseTls {
		//send madatory-negotitaion tls feature
		_, err := fmt.Fprint(s.w, "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"+
       				"<required/>"+
     				"</starttls>"+
   					"</stream:features>")
		if err != nil { return err }
	} else {
		sasl := NewSasl(s)
		if err := sasl.talking(); err != nil { return err }

		fmt.Println("=====in loop====")
		for {
			_,err := nextStart(s.dec)
			if err != nil {
				fmt.Println("=====in loop error====")
				return err
			}
		}
	}
	return nil
}

func (s *Session) talkingInitStream() error {
	/*
	Step 1:
	<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' 
		to="lxtap.com" version="1.0">
	*/
	ele, err := nextStart(s.dec)
	if err != nil {
		log.Fatalln(err)
		fmt.Fprint(s.w, xmppErr(xmppErrNotWellFormed))
		fmt.Fprint(s.w, xmppStreamEnd)
		return err
	}
	
	st, err := decodeStreamStart(&ele)
	if err != nil {
		log.Fatalln(err)
		return err
	}
	if st.Name.Space != xmppNsStream && st.Name.Local != "stream" {
		fmt.Fprint(s.w, xmppErr(xmppErrInvalidNamespace))
		fmt.Fprint(s.w, xmppStreamEnd)
		return nil
	}
	if !s.srv.cfg.DebugEnable || s.srv.cfg.Host != "" && s.srv.cfg.Host != st.To {
		log.Fatalln("Stream host does not match server")
		fmt.Fprint(s.w, xmppErr(xmppErrHostUnknown))
		fmt.Fprint(s.w, xmppStreamEnd)
		return errors.New("host not match")
	}

	if st.Version != "1.0" {
		//this compare is not valid.
		//TBD: Refer RFC6120 4.7.5. version
		fmt.Fprint(s.w, xmppErr(xmppErrUnsupportedVersion))
		fmt.Fprint(s.w, xmppStreamEnd)
		return nil
	}
	//Response Stream
	streamId := s.srv.idg.NextId()

	toAttr := ""
	if st.To != "" {
		toAttr = fmt.Sprintf("to='%s'", escapeXml(st.To))
	} 
	_, err = fmt.Fprintf(s.w, "<?xml version='1.0'?><stream:stream "+
       "from='%s' id='%s' %s version='1.0' "+
       "xml:lang='en' xmlns='jabber:client' "+
       "xmlns:stream='http://etherx.jabber.org/streams'>", escapeXml(s.srv.cfg.Host),
       	streamId, toAttr)
	
	//fmt.Printf("%v\n", st)
	
	return err
}

func (s *Session) TalingSeconds() int64 {
	return time.Now().Unix() - s.CallinTime
}


/*
A reader tunnel:
For debug
*/
type readTunnel struct {
    r io.Reader
    w io.Writer
}

func (t readTunnel) Read(p []byte) (n int, err error) {
    n, err = t.r.Read(p)
    if n > 0 {
    	t.w.Write([]byte("-------Read data--------\n"))
        t.w.Write(p[0:n])
        t.w.Write([]byte("\n\n"))
    }
    return n, err
}

/*
A writer tunnel:
For debug
*/
type writeTunnel struct {
	w io.Writer
	reWriter io.Writer
}
func (t writeTunnel) Write(p []byte) (n int, err error) {
	n, err = t.w.Write(p)
	if n > 0 {
		t.reWriter.Write([]byte("------Write to--------\n"))
		t.reWriter.Write(p[0:n])
		t.reWriter.Write([]byte("\n\n"))
	}
	return n, err
}