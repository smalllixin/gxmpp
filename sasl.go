package gxmpp

import (
	"fmt"
	"log"
	"errors"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"crypto/md5"
	"crypto/sha1"
	"crypto/hmac"
	"strings"
)

type ScramServerState struct {
	ClientFirstMessage string
	Gs2Header string
	ClientFirstMessageBare string
	Username string
	ClientNonce string
	ServerNonce string
	Nonce string
	UserSalt []byte
	ServerFirstMessage string
	ClientProof []byte
	SaltedPassword  []byte
    ClientKey []byte
    StoredKey []byte
    AuthMessage string
    ClientSignature []byte
    ServerKey []byte
    ServerSignature []byte
    IterCount int
}

/*
TBD: mess error handle
*/

type Sasl struct {
	session *Session
	srvCfg *ServerConfig
	supportedMechanisms []string
}

func NewSasl(session *Session) *Sasl {
	s := new(Sasl)
	s.session = session
	s.srvCfg = session.srv.cfg
	s.supportedMechanisms = []string {"PLAIN", "SCRAM-SHA-1", "DIGEST-MD5"}
	return s
}

func (s *Sasl) talking() error {
	/*
	if s.session.tlsFeatureSuccess {
		supportMechanisms = append(supportMechanisms, "PLAIN")
	}
	*/
	mechanismsStreamFeature := mechanismBuilder()
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
	case "SCRAM-SHA-1":
		if err = s.auth_SCRAM_SHA_1(authEle); err != nil {
			return err
		}
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

//Refer RFC5802
/*
HMAC(key, str): Apply the HMAC keyed hash algorithm
H(str): Apply the cryptographic hash function to the octet string
      "str", producing an octet string as a result.
Hi(str, salt, i):
    U1   := HMAC(str, salt + INT(1))
    U2   := HMAC(str, U1)
    ...
    Ui-1 := HMAC(str, Ui-2)
    Ui   := HMAC(str, Ui-1)

    Hi := U1 XOR U2 XOR ... XOR Ui

    where "i" is the iteration count, "+" is the string concatenation
      operator, and INT(g) is a 4-octet encoding of the integer g, most
      significant octet first.
-----------
     SaltedPassword  := Hi(Normalize(password), salt, i)
     ClientKey       := HMAC(SaltedPassword, "Client Key")
     StoredKey       := H(ClientKey)
     AuthMessage     := client-first-message-bare + "," +
                        server-first-message + "," +
                        client-final-message-without-proof
     ClientSignature := HMAC(StoredKey, AuthMessage)
     ClientProof     := ClientKey XOR ClientSignature
     ServerKey       := HMAC(SaltedPassword, "Server Key")
     ServerSignature := HMAC(ServerKey, AuthMessage)
------------
This is a simple example of a SCRAM-SHA-1 authentication exchange
   when the client doesn't support channel bindings (username 'user' and
   password 'pencil' are used):

   C: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
   S: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,
      i=4096
   C: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,
      p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
   S: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=

*/
func (s *Sasl) auth_SCRAM_SHA_1(authEle *saslAuth) error {
	get_client_first_message := func () (string, error) {
		message, err := base64.StdEncoding.DecodeString(authEle.Body)
		if err != nil {
			fmt.Fprint(s.session.w, saslError(saslErrIncorrectEncoding))
			return "", err
		}
		return string(message), nil
	}
	gen_server_nonce := func () string {
		return s.gen_nonce()
	}
	get_client_final_message := func() (string,error) {
		response, err := s.readResponse()
		if err != nil {
			fmt.Fprint(s.session.w, saslError(saslErrIncorrectEncoding))
			return "", err
		}
		return response, nil
		//return "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
	}
	get_passwd := func(username string) string {
		return "pencil"
	}
	err_ret := func() error{
		return errors.New("message invalid")
	}

	challengeWriter := func(content string) error {
		b := base64.StdEncoding.EncodeToString([]byte(content))
		_, err := fmt.Fprintf(s.session.w, "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>%s</challenge>",b)
		return err
	}

	successWriter := func(content string) error {
		b := base64.StdEncoding.EncodeToString([]byte(content))
		_, err := fmt.Fprintf(s.session.w, 
			"<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'></success>",b)
		return err
	}

	var err error

	st := new(ScramServerState)
	//(username 'user' and password 'pencil' are used):
	if st.ClientFirstMessage, err = get_client_first_message(); err != nil {
		return err_ret()
	}
	
	sm := strings.Split(st.ClientFirstMessage, ",")
	if len(sm) < 4 {
		return err_ret()
	}
	if !(sm[0] == "n" || sm[0] == "y" || sm[0] == "p") {
		return err_ret()
	}
	commaI := 0
	searchIdx := strings.IndexRune(st.ClientFirstMessage, ',')
	if searchIdx == -1 { return err_ret() }
	commaI += searchIdx
	searchIdx = strings.IndexRune(st.ClientFirstMessage[commaI+1:], ',')
	if searchIdx == -1 { return err_ret() }
	commaI += searchIdx + 1
	
	st.Gs2Header = st.ClientFirstMessage[:commaI+1] // +1 for include comma
	//fmt.Printf("GS2_Header:%s\n", GS2_Header)
	st.ClientFirstMessageBare = st.ClientFirstMessage[commaI+1:]
	//client_first_message_bare := st.ClientFirstMessage[commaI+1:]
	//fmt.Printf("client_first_message_bare:%s\n", client_first_message_bare)

	tokens := map[string]string{}
	for _, token := range sm[2:] {
		kv := strings.SplitN(strings.TrimSpace(token), "=", 2)
		if len(kv) == 2 {
			tokens[kv[0]] = kv[1]
		}
	}
	var n,r string
	var ok bool
	if n, ok = tokens["n"]; !ok {
		return err_ret()
	}
	if r, ok = tokens["r"]; !ok {
		return err_ret()	
	}
	st.Username = n
	st.ClientNonce = r
	// client_nonce := r
	st.ServerNonce = gen_server_nonce()
	// server_nonce := gen_server_nonce()
	//fmt.Println(username)
	//fmt.Println(client_nonce)
	st.UserSalt = make([]byte, 8*3)
	s.session.randMaker.Read(st.UserSalt)
	// gen_random_salt(st.UserSalt)
	salt := base64.StdEncoding.EncodeToString(st.UserSalt)

	st.IterCount = 4096

	nonce := st.ClientNonce + st.ServerNonce
	st.ServerFirstMessage = fmt.Sprintf("r=%s,s=%s,i=%d",nonce,salt,st.IterCount)
	// server_first_message := fmt.Sprintf("r=%s,s=%s,i=%d",nonce,salt,st.IterCount)
	if err = challengeWriter(st.ServerFirstMessage); err != nil {
		return err_ret()
	}

	// fmt.Println(st.ServerFirstMessage)
	/*
	Client final message:
	C: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
	---which ---
	r: the nonce
	c: GS2 header:which include authzid&channel bind (normally base64(n,,))
	p: base64(ClientProof)
	*/

	//reuse token map here.
	st.ClientFirstMessage, err = get_client_final_message()
	if err != nil {
		return err_ret()
	}
	// client_final_message := get_client_final_message()
	for _, token := range strings.Split(st.ClientFirstMessage,",") {
		kv := strings.SplitN(strings.TrimSpace(token), "=", 2)
		if len(kv) == 2 {
			tokens[kv[0]] = kv[1]
		}
	}
	var c,p string
	if c,ok = tokens["c"]; !ok {
		return err_ret()
	}
	if p,ok = tokens["p"]; !ok {
		return err_ret()
	}

	proofIdx := strings.LastIndex(st.ClientFirstMessage, ",p=")
	if proofIdx == -1 { return err_ret() }
	client_final_message_without_proof := st.ClientFirstMessage[:proofIdx]

	c_GS2_Header,err := base64.StdEncoding.DecodeString(c)
	_ = c_GS2_Header //just ignore. TBD channel & authzid resolve
	if err != nil {
		return err_ret()
	}
	//compute ClientProof
	/*
	SaltedPassword  := Hi(Normalize(password), salt, i)
     ClientKey       := HMAC(SaltedPassword, "Client Key")
     StoredKey       := H(ClientKey)
     AuthMessage     := client-first-message-bare + "," +
                        server-first-message + "," +
                        client-final-message-without-proof
     ClientSignature := HMAC(StoredKey, AuthMessage)
     ClientProof     := ClientKey XOR ClientSignature
     ServerKey       := HMAC(SaltedPassword, "Server Key")
     ServerSignature := HMAC(ServerKey, AuthMessage)
	*/
	var comingClientProof []byte
	if comingClientProof,err = base64.StdEncoding.DecodeString(p); err != nil {
		return err_ret()
	}
	passwd := get_passwd(st.Username)

	//
	st.SaltedPassword = _Hi([]byte(passwd), st.UserSalt, st.IterCount)
	// fmt.Printf("SaltedPassword:%s\n", hex.EncodeToString(SaltedPassword))
	
	st.ClientKey = sha1_hmac(st.SaltedPassword, []byte("Client Key"))
	// fmt.Printf("ClientKey:%s\n", hex.EncodeToString(ClientKey))

	st.StoredKey = sha1_bytes(st.ClientKey)
	// fmt.Printf("StoredKey:%s\n", hex.EncodeToString(StoredKey))

	//Compute AuthMessage
	st.AuthMessage = fmt.Sprintf("%s,%s,%s", st.ClientFirstMessageBare, st.ServerFirstMessage, 
		client_final_message_without_proof)
	// fmt.Printf("AuthMessage:%s\n", st.AuthMessage)

	st.ClientSignature = sha1_hmac(st.StoredKey, []byte(st.AuthMessage))

	st.ClientProof = make([]byte, sha1.Size)
	
	for k := 0; k < sha1.Size; k ++ {
		st.ClientProof[k] = st.ClientKey[k]^st.ClientSignature[k]
	}

	// fmt.Printf("ComputeClientProof:%s\nComingClientProof:%s\n", 
	// 		hex.EncodeToString(st.ClientProof), hex.EncodeToString(comingClientProof))
	if bytes.Compare(st.ClientProof,comingClientProof) == 0 {
		fmt.Println("Success")
	} else {
		fmt.Println("Failured")
	}
	st.ServerKey = sha1_hmac(st.SaltedPassword, []byte("Server Key"))
	st.ServerSignature = sha1_hmac(st.ServerKey, []byte(st.AuthMessage))
	err = successWriter("v="+base64.StdEncoding.EncodeToString(st.ServerSignature))
	if err != nil {
		return err_ret()
	}

	return nil
}

func (s *Sasl) readResponse() (string, error) {
	_, ele, err := next(s.session.dec)
	if err != nil { log.Println(err); return "", err }
	var respEle *saslResponse
	switch ele.(type) {
	default:
		err = errors.New("expected <response/>")
		log.Println(err)
		return "", err
	case *saslResponse:
		respEle = ele.(*saslResponse)
	case *saslAbort:
		fmt.Fprint(s.session.w, saslError(saslErrAborted))
		return "", err
	}
	if respEle.Body != "" {
		response, err := base64.StdEncoding.DecodeString(respEle.Body)
		return string(response), err
	} else {
		return "", nil
	}	
}

func (s *Sasl) auth_DIGEST_MD5() error {
	//realm:
	realm := s.srvCfg.Host //like lxtap.com
	_ = realm
	/*
	realm="somerealm",nonce="OA6MG9tEQGm2hh",\
				qop="auth",charset=utf-8,algorithm=md5-sess
	*/
	nonce := s.gen_nonce()
	challenge := saslDigestMd5Challenge(s.srvCfg.Host, nonce, "auth", "utf-8", "md5-sess")
	fmt.Fprint(s.session.w, challenge)
	response, err := s.readResponse()
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
		_, err := s.readResponse()
		_, ok = err.(base64.CorruptInputError) //this trick for Spark write a weird "=" response.
		if err != nil && !ok {
			fmt.Fprint(s.session.w, saslError(saslErrIncorrectEncoding))
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


// Generate nonce 
func (s *Sasl) gen_nonce() string {
	nonce := make([]byte, 8*4)
	s.session.randMaker.Read(nonce)
	return base64.StdEncoding.EncodeToString(nonce)
}

func (s *Sasl) mechanismBuilder() string {
	var buffer bytes.Buffer
	buffer.WriteString("<stream:features>")
	buffer.WriteString("<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>")
	for i := 0; i < len(s.supportedMechanisms); i ++ {
		buffer.WriteString("<mechanism>"+s.supportedMechanisms[i]+"</mechanism>")
	}
	buffer.WriteString("</mechanisms>")

	buffer.WriteString("</stream:features>")
	return buffer.String()
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

/////

func _Hi(str, salt []byte, iter_count int) []byte {
	temp := salt
	bstr := str
	sLen := len(salt)
	temp = append(temp, 0x00, 0x00, 0x00, 0x00) 
	var lastU []byte
	hlen := sha1.Size //sha1 block size: which is 20
	T := make([]byte, hlen)
	for u := 1; u <= iter_count; u ++ { 
		if u == 1 {
			//salt + INT(1)
			int1 := uint32(1)
			temp[sLen+0] = byte((int1 & 0xff000000) >> 24);
			temp[sLen+1] = byte((int1 & 0x00ff0000) >> 16);
            temp[sLen+2] = byte((int1 & 0x0000ff00) >> 8);
            temp[sLen+3] = byte((int1 & 0x000000ff) >> 0);
            lastU = sha1_hmac(bstr, temp)
		} else {
			lastU = sha1_hmac(bstr, lastU)
		}
		for k := 0; k < hlen; k ++ {
			T[k] ^= lastU[k]
		}
	}
	return T
}



func sha1_hmac(str, salt []byte) []byte {
	mac := hmac.New(sha1.New, str)
	mac.Write(salt)
	return mac.Sum(nil)
	//return hex.EncodeToString(mac.Sum(nil))
}

func sha1_bytes(str []byte) []byte {
	h := sha1.New()
	h.Write([]byte(str))
	return h.Sum(nil)
}

//////
func md5hash(text string) string {
    hasher := md5.New()
    hasher.Write([]byte(text))
    return hex.EncodeToString(hasher.Sum(nil))
}

func sha1hash(text string) string {
	h := sha1.New()
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

func saslDigestMd5Challenge(realm, nonce, qop, charset, algorithm string) string {
	challenge := fmt.Sprintf(`realm="%s",nonce="%s",qop="%s",charset="%s",algorithm="%s"`,
					realm, nonce, qop, charset, algorithm)
	challenge = base64.StdEncoding.EncodeToString([]byte(challenge))
	return fmt.Sprintf("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>%s</challenge>",challenge)
}

func saslError(name string) string {
	return fmt.Sprintf("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><%s/></failure>",name)
}


