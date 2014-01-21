package gxmpp

import (
	"fmt"
	"log"
	"errors"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"crypto/rand"
	"crypto/md5"
	"math/big"
	"strings"
)

type Sasl struct {
	session *Session
	srvCfg *ServerConfig
}

func NewSasl(session *Session) *Sasl {
	s := new(Sasl)
	s.session = session
	s.srvCfg = session.srv.cfg
	return s
}

func (s *Sasl) talking() error {
	supportMechanisms := []string {"PLAIN",",SCRAM-SHA-1-PLUS", "SCRAM-SHA-1", "DIGEST-MD5"}
	/*
	if s.session.tlsFeatureSuccess {
		supportMechanisms = append(supportMechanisms, "PLAIN")
	}
	*/
	mechanismsStreamFeature := _mechanismBuilder(supportMechanisms)
	_, err := fmt.Fprint(s.session.w, mechanismsStreamFeature)
	if err != nil { return err }
	//client will send <auth/>
	//<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'
    //     mechanism='xxxx'>base64 encoded</auth>
	_, ele, err := next(s.session.dec)
	if err != nil {
		log.Println(err)
		return err
	}
	var ok bool
	var authEle *saslAuth
	authEle, ok = ele.(*saslAuth)
	if !ok {
		err = errors.New("expected <auth/>")
		log.Println(err)
		return err
	}

	switch authEle.Mechanism {
	case "DIGEST-MD5":
		if err = s.auth_DIGEST_MD5(); err != nil {
			return err
		}
	case "PLAIN":
		if err = s.auth_PLAIN(authEle); err != nil {
			return err
		}
	default:

	}
	
	//THEN challenge-response for specified mechanism

	//Util Abort
	//I: <abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>
	//R: <failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
    // 		<aborted/>
	//   </failure>

	/*
	Or SASL for specified mechanism failure
	R: <failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
     <not-authorized/>
   </failure>
	*/
	return nil
}

func (s *Sasl) auth_PLAIN(authEle *saslAuth) error {
	message, err := base64.StdEncoding.DecodeString(authEle.Body)
	if err != nil {
		fmt.Fprint(s.session.w, saslError(saslErrIncorrectEncoding))
		return err
	}
	splitMsg := strings.Split(string(message),"\x00")
	if len(splitMsg) != 3 {
		fmt.Fprint(s.session.w, saslError(saslErrIncorrectEncoding))
		return errors.New("rfc4616: sasl PLAIN encoding incorrect")
	}

	authzid := splitMsg[0]
	authcid := splitMsg[1]
	passwd := splitMsg[2]
	if authcid == "" || passwd == "" {
		fmt.Fprintf(s.session.w, saslError(saslErrNotAuthorized))
		return errors.New("auth failure")
	}

	if md5hash("sa123456") == md5hash(passwd) {
		//TBD Authorize test here
		_ = authzid
		fmt.Fprint(s.session.w,"<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
		s.session.saslFeatureSuccess = true
		fmt.Println("auth_PLAIN success")
	} else {
		fmt.Fprintf(s.session.w, saslError(saslErrNotAuthorized))
		return errors.New("auth failure")
	}

	return nil
}

func (s *Sasl) auth_DIGEST_MD5() error {
	//realm:
	realm := s.srvCfg.Host //like lxtap.com
	_ = realm
	/*
	realm="somerealm",nonce="OA6MG9tEQGm2hh",\
				qop="auth",charset=utf-8,algorithm=md5-sess
	*/
	nonce := gen_nonce()
	challenge := saslDigestChallenge(s.srvCfg.Host, nonce, "auth", "utf-8", "md5-sess")
	fmt.Fprint(s.session.w, challenge)
	/*fmt.Fprint(s.session.w,"<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"+
			"cmVhbG09InNvbWVyZWFsbSIsbm9uY2U9Ik9BNk1HOXRFUUdtMmhoIixxb3A9ImF1dGgi"+
			"LGNoYXJzZXQ9dXRmLTgsYWxnb3JpdGhtPW1kNS1zZXNzCg=="+
			"</challenge>")
			*/
	_, ele, err := next(s.session.dec)
	if err != nil { log.Println(err); return err }
	var respEle *saslResponse
	switch ele.(type) {
	default:
		err = errors.New("expected <response/>")
		log.Println(err)
		return err
	case *saslResponse:
		respEle = ele.(*saslResponse)
	case *saslAbort:
		fmt.Fprint(s.session.w, saslError(saslErrAborted))
		return err
	}

	response, err := base64.StdEncoding.DecodeString(respEle.Body)
	if err != nil {
		fmt.Fprint(s.session.w, saslError(saslErrIncorrectEncoding))
		return err
	}

	/*
	SASL Digest-response = 1# (username=“username”| realm | nonce | [cnonce=cnonce] |
	 [nc=nonce-count] | [qop=message-qop] | uri=digest-uri | response="response” | 
	 [maxbuf=maxbuf] | [charset=charset] | cipher=cipher | [authzid=authzid] | 
	 [auth-param]
	 )
	
	username="test",realm="lxtap.com",nonce="4975828c9fb113eb",
	cnonce="/mK6t9FDPxYr4miW6cwXeZMo5w4+EVZ6cdHP2vjqkSI=",
	nc=00000001,qop=auth,maxbuf=4096,digest-uri="xmpp/lxtap.com",
	response=c9dc06977250b664cc31f7f2cbfca073,charset=utf-8
	*/
	//TBD parse response
	tokens := map[string]string{}
	for _, token := range strings.Split(string(response), ",") {
		kv := strings.SplitN(strings.TrimSpace(token), "=", 2)
		if len(kv) == 2 {
			if kv[1][0] == '"' && kv[1][len(kv[1])-1] == '"' {
				kv[1] = kv[1][1 : len(kv[1])-1]
			}
			tokens[kv[0]] = kv[1]
		}
	}

	if tokens["digest-uri"] != ("xmpp/"+s.srvCfg.Host) {
		//TBD sasl error response
		return errors.New("digest-uri not expected")
	}
	_,ok := tokens["response"]
	if !ok {
		//TBD sasl error response
		return errors.New("Digest response not expected")
	}
	_,ok = tokens["authzid"]
	if !ok {
		tokens["authzid"] = ""
	}
	serverDigest := _DIGEST_MD5_response_value(tokens["username"], tokens["realm"], "sa123456",
		nonce, tokens["nc"], tokens["cnonce"], tokens["digest-uri"], tokens["authzid"], false)
	// fmt.Println("-------Digest Compare--------")
	// fmt.Printf("client:%s\n", tokens["response"])
	// fmt.Printf("server:%s\n", serverDigest)
	// fmt.Println("-------END Digest Compare--------")
	if tokens["response"] == serverDigest {
		
		//auth success
		rspauth := _DIGEST_MD5_response_value(tokens["username"], tokens["realm"], "sa123456",
			nonce, tokens["nc"], tokens["cnonce"], tokens["digest-uri"], tokens["authzid"],
			true)
		challenge = "rspauth="+rspauth
		_, err = fmt.Fprintf(s.session.w, "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>%s</challenge>",
			base64.StdEncoding.EncodeToString([]byte(challenge)))

		//receive the final reponse
		_, ele, err = next(s.session.dec)
		if err != nil { log.Println(err); return err }
		switch ele.(type) {
		default:
			err = errors.New("expected <response/>")
			log.Println(err)
			return err
		case *saslResponse:
			respEle = ele.(*saslResponse)
		case *saslAbort:
			fmt.Fprintf(s.session.w, saslError(saslErrAborted))
			return err
		}
		
		fmt.Fprint(s.session.w,"<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
		s.session.saslFeatureSuccess = true
	} else {
		/*
		<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>
		    <invalid-authzid/>
		</failure>
		*/
		fmt.Fprintf(s.session.w, saslError(saslErrNotAuthorized))
		return errors.New("auth failure")//TBD. loop auth instead just close
	}

	return nil
}

//qop must present as auth: just support auth in gxmpp
//algorithm support md5-sess
//rfc2831:2.1.2.1 for details
func _kd(secret, data string) string {
	return md5hash(secret + ":" + data)
}

func _DIGEST_MD5_response_value(username, realm, passwd, nonce, nc, cnonce, digestUri, 
		authzid string, rspauth bool) string{
	h := func(text string) []byte {
		h := md5.New()
		h.Write([]byte(text))
		return h.Sum(nil)
	}
	// fmt.Printf("\n====compute\n")
	// fmt.Println(username, realm, passwd, nonce, nc, cnonce, digestUri)
	// fmt.Println(string(h(username+":"+realm+":"+passwd)))
	// fmt.Printf("\n====end compute\n")
	var A1,A2 string
	if authzid == "" {
		A1 = string(h(username+":"+realm+":"+passwd))+":"+nonce+":"+cnonce
	} else {
		A1 = string(h(username+":"+realm+":"+passwd))+":"+nonce+":"+cnonce+":"+authzid
	}
	if !rspauth {
		A2 = "AUTHENTICATE:"+digestUri
	} else {
		A2 = ":" + digestUri
	}
	// fmt.Println("----a1----")
	// fmt.Println(A1)
	// fmt.Println("-----a2---")
	// fmt.Println(A2)
	// fmt.Println("--------")
	d := _kd(md5hash(A1), nonce+":"+nc+":"+cnonce+":auth:"+md5hash(A2))
	return d
}

func md5hash(text string) string {
    hasher := md5.New()
    hasher.Write([]byte(text))
    return hex.EncodeToString(hasher.Sum(nil))
}

// Generate nonce 
func gen_nonce() string {
	randSize := big.NewInt(0)
	randSize.Lsh(big.NewInt(1), 64)
	cn, err := rand.Int(rand.Reader, randSize)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%016x", cn)
}

func saslDigestChallenge(realm, nonce, qop, charset, algorithm string) string {
	challenge := fmt.Sprintf(`realm="%s",nonce="%s",qop="%s",charset="%s",algorithm="%s"`,
					realm, nonce, qop, charset, algorithm)
	challenge = base64.StdEncoding.EncodeToString([]byte(challenge))
	return fmt.Sprintf("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>%s</challenge>",challenge)
}

func saslError(name string) string {
	return fmt.Sprintf("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><%s/></failure>",name)
}


func _mechanismBuilder(mechanisms []string) string {
	var buffer bytes.Buffer
	buffer.WriteString("<stream:features>"+
     		"<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>")
	for i := 0; i < len(mechanisms); i ++ {
		buffer.WriteString("<mechanism>"+mechanisms[i]+"</mechanism>")
	}
   	buffer.WriteString("</mechanisms></stream:features>")
   	return buffer.String()
}