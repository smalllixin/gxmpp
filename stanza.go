package gxmpp


import (
	"fmt"
	"encoding/xml"
  "bytes"
  "errors"
  "io"
)

var _ = io.EOF

type streamStart struct {
	Name xml.Name `xml:"http://etherx.jabber.org/streams stream"`
	From string `xml:"from,attr"`	//From 
	To string `xml:"to,attr"`
	Version string `xml:"version,attr"`
	Lang string `xml:"xml lang,attr"`
	NS string `xml:"xmlns,attr"`
}

type saslAuth struct {
  Name xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl auth"`
  Mechanism string `xml:"mechanism,attr"`
  NS string `xml:"xmlns,attr"`
  Body string `xml:",chardata"`
}

type saslResponse struct {
  Name xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl response"`
  Body string `xml:",chardata"`
}

type saslAbort struct {
  Name xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl abort"`
}

const (
	xmppStreamEnd = "</stream:stream>"
	xmppNsStream = "http://etherx.jabber.org/streams"
  xmppNsTLS    = "urn:ietf:params:xml:ns:xmpp-tls"
  xmppNsSASL   = "urn:ietf:params:xml:ns:xmpp-sasl"
  xmppNsBind   = "urn:ietf:params:xml:ns:xmpp-bind"
  xmppNsClient = "jabber:client"
)

/*
usage:
	xmppErr(xmppErrBadFormat)
*/

func xmppErr(errName string) string {
	return fmt.Sprintf("<stream:error><%s xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"+
			"</stream:error>", errName)
}

const (
    //Stream Errors Are Unrecoverable
    //rfc6120

    //4.9.3.1.
    xmppErrBadFormat = "bad-format"

    //4.9.3.2.
    xmppErrBadNamespacePrefix = "bad-namespace-prefix"

    //4.9.3.3.
    xmppErrConflict = "conflict"

    //4.9.3.4.
    xmppErrConnectionTimeout = "connection-timeout"

    //4.9.3.5. host-gone
    xmppErrHostGone = "host-gone"

    //4.9.3.6. host-unknown
    xmppErrHostUnknown = "host-unknown"

    //4.9.3.7. improper-addressing
    xmppErrImproperAddressing = "improper-addressing"

    //4.9.3.8. internal-server-error
   	xmppErrInternalServerError = "internal-server-error"

   	//4.9.3.9. invalid-from
    xmppErrInvalidFrom = "invalid-from"

    //4.9.3.10. invalid-namespace
    xmppErrInvalidNamespace = "invalid-namespace"

    //4.9.3.11. invalid-xml
    xmppInvalidXml = "invalid-xml"

   	//4.9.3.12. not-authorized
   	xmppNotAuthorized = "not-authorized"

    //4.9.3.13. not-well-formed
    xmppErrNotWellFormed = "not-well-formed"

    //4.9.3.14. policy-violation. 
    //NOTE: The reason of this error need parameterize. And this is not right yet.
    xmppPolicyViolation = "policy-violation"

    //4.9.3.15. remote-connection-failed
    xmppRemoteConnectionFailed = "remote-connection-failed"
    //4.9.3.16. reset
    xmppErrReset = "reset"
   	//4.9.3.17. resource-constraint
   	xmppErrResourceConstraint = "resource-constraint"
   	//4.9.3.18. restricted-xml
   	xmppErrRestrictedXml = "restricted-xml"
   	//4.9.3.19. see-other-host.
   	//NOTE:the other host need parameterize. This is not right yet.
   	xmppErrSeeOtherHost = "see-other-host"
   	//4.9.3.20. system-shutdown
   	xmppErrSystemShutDown = "system-shutdown"
   	//4.9.3.21. undefined-condition
   	xmppErrUndefinedCondition = "undefined-condition"
   	//4.9.3.22. unsupported-encoding
   	xmppErrUnsupportedEncoding = "unsupported-encoding"
   	//4.9.3.23. unsupported-feature
   	xmppErrUnsupportedFeature = "unsupported-feature"
   	//4.9.3.24. unsupported-stanza-type
   	xmppErrUnsupportedStanzaType = "unsupported-stanza-type"
   	//4.9.3.25. unsupported-version
   	xmppErrUnsupportedVersion = "unsupported-version"
   	//4.9.4. Application-Specific Conditions
   	//TBD
)

const (
    saslErrAborted = "abort"
    saslErrAccountDisabled = "account-disabled"
    saslErrCredentialsExpired = "credentials-expired"
    saslErrEncryptionRequired = "encryption-required"
    saslErrIncorrectEncoding = "incorrect-encoding"
    saslErrInvalidAuthzid = "invalid-authzid"
    saslErrInvalidMechanism = "invalid-mechanism"
    saslErrMalformedRequest = "malformed-request"
    saslErrMechanismTooWeak = "mechanism-too-weak"
    saslErrNotAuthorized = "not-authorized"
    saslErrTemporaryAuthFailure = "temporary-auth-failure"
)



func escapeXml(s string) string {
  buf := new(bytes.Buffer)
  buf.Grow(len(s))
  err := xml.EscapeText(buf, []byte(s))
  if err != nil {
    panic(err)
  }
  return buf.String()
}


// Scan XML token stream for next element and save into val.
// If val == nil, allocate new element based on proto map.
// Either way, return val.
func next(p *xml.Decoder) (xml.Name, interface{}, error) {
  // Read start element to find out what type we want.
  se, err := nextStart(p)
  if err != nil {
    return xml.Name{}, nil, err
  }

  // Put it in an interface and allocate one.
  var nv interface{}
  switch se.Name.Space + " " + se.Name.Local {
    /*
  case xmppNsStream + " features":
    nv = &streamFeatures{}
  case xmppNsStream + " error":
    nv = &streamError{}
  case xmppNsTLS + " starttls":
    nv = &tlsStartTLS{}
  case xmppNsTLS + " proceed":
    nv = &tlsProceed{}
  case xmppNsTLS + " failure":
    nv = &tlsFailure{}
    */
  case xmppNsSASL + " auth":
    nv = &saslAuth{}
  case xmppNsSASL + " response":
    nv = &saslResponse{}
  case xmppNsSASL + " abort":
    nv = &saslAbort{}
  /*
  case xmppNsSASL + " mechanisms":
    nv = &saslMechanisms{}
  case xmppNsSASL + " challenge":
    nv = ""
  case xmppNsSASL + " response":
    nv = ""
  case xmppNsSASL + " success":
    nv = &saslSuccess{}
  case xmppNsSASL + " failure":
    nv = &saslFailure{}
  case xmppNsBind + " bind":
    nv = &bindBind{}
  case xnmppNsClient + " message":
    nv = &clientMessage{}
  case xnmppNsClient + " presence":
    nv = &clientPresence{}
  case xnmppNsClient + " iq":
    nv = &clientIQ{}
  case xnmppNsClient + " error":
    nv = &clientError{}
    */
  default:
    return xml.Name{}, nil, errors.New("unexpected XMPP message " +
      se.Name.Space + " <" + se.Name.Local + "/>")
  }

  // Unmarshal into that storage.
  if err = p.DecodeElement(nv, &se); err != nil {
    return xml.Name{}, nil, err
  }
  return se.Name, nv, err
}

// Scan XML token stream to find next StartElement.
func nextStart(p *xml.Decoder) (xml.StartElement, error) {
  for {
    t, err := p.Token()
    if err != nil/* && err != io.EOF */{
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

