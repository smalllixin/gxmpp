package gxmpp


import (
	"fmt"
	"encoding/xml"
)

type streamStart struct {
	Name xml.Name `xml:"http://etherx.jabber.org/streams stream"`
	From string `xml:"from,attr"`	//From 
	To string `xml:"to,attr"`
	Version string `xml:"version,attr"`
	Lang string `xml:"xml lang,attr"`
	NS string `xml:"xmlns,attr"`
}

const (
	xmppStreamEnd = "</stream:stream>"
	xmppNsStream = "http://etherx.jabber.org/streams"
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



