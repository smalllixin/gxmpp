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


type Session struct {
	conn net.Conn
	w io.Writer 	//to client writer
	srv *Server
	CallinTime int64 //unix timestamp
	dec *xml.Decoder
	enc *xml.Encoder
}

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
	return s
}

func (s *Session) Talking() {
	defer s.conn.Close()
	if err := s.stanzaStream(); err != nil {
		return
	}
}

func (s *Session) stanzaStream() error {
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
	if s.srv.cfg.Host != "" && s.srv.cfg.Host != st.To {
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

	fmt.Fprintf(s.w, "<?xml version='1.0'?><stream:stream "+
       "from='%s' id='%s' to='juliet@im.example.com' version='1.0' "+
       "xml:lang='en' xmlns='jabber:client' "+
       "xmlns:stream='http://etherx.jabber.org/streams'>", escapeXml(s.srv.cfg.Host),
       	streamId)

	//fmt.Printf("%v\n", st)
	
	return nil
}

func (s *Session) TalingSeconds() int64 {
	return time.Now().Unix() - s.CallinTime
}

func escapeXml(s string) string {
	buf := new(bytes.Buffer)
	buf.Grow(len(s))
	err := xml.EscapeText(buf, []byte(s))
	if err != nil {
		panic(err)
	}
	return buf.String()
}

// Scan XML token stream to find next StartElement.
func nextStart(p *xml.Decoder) (xml.StartElement, error) {
	for {
		t, err := p.Token()
		if err != nil && err != io.EOF {
			return xml.StartElement{}, err
		}
		switch t := t.(type) {
		case xml.StartElement:
			return t, nil
		}
	}
	panic("unreachable")
}

func decodeStreamStart(e *xml.StartElement) (*streamStart, error) {
	/*
	<stream:stream
       from='juliet@im.example.com'
       to='im.example.com'
       version='1.0'
       xml:lang='en'
       xmlns='jabber:client'
       xmlns:stream='http://etherx.jabber.org/streams'>

       {{http://etherx.jabber.org/streams stream} [{
	       { xmlns} jabber:client} 
	       {{xmlns stream} http://etherx.jabber.org/streams}
	       {{ to} lxtap.com}
	       {{ version} 1.0}
	    ]}
	*/
	st := new(streamStart)
	st.Name.Space = e.Name.Space
	st.Name.Local = e.Name.Local
	for i := 0; i < len(e.Attr); i ++ {
		attr := e.Attr[i] // Attr{Name,Value}
		switch attr.Name.Local {
		case "from":
			st.From = attr.Value
		case "to":
			st.To = attr.Value
		case "version":
			st.Version = attr.Value
		case "lang":
			st.Lang = attr.Value
		}
	}
	return st, nil
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
        t.w.Write(p[0:n])
        t.w.Write([]byte("\n"))
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
		t.reWriter.Write(p[0:n])
		t.w.Write([]byte("\n"))
	}
	return n, err
}