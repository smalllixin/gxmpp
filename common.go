package gxmpp

import (
)
/**
Some global struct and const defined here.
*/

type ServerConfig struct {
	DebugEnable bool
	C2SPort string	//the port listen for the client-server
	S2SEnable bool	//not prepare implement yet
	S2SPort string
	UseTls bool
	Host string //the server host. If don't want to valid it. Leave it alone.

	//default port 5223 listen the client use SSL connected in directly.
}

var emptyConfig ServerConfig

var _hasInited bool
func initDefaultConfig() {
	emptyConfig.DebugEnable = true
	emptyConfig.C2SPort = "0.0.0.0:5222"
	emptyConfig.S2SEnable = false
	emptyConfig.S2SPort  = "0.0.0.0:5269"
	emptyConfig.UseTls = false
	emptyConfig.Host = ""
}

func DefaultConfig() *ServerConfig {
	if !_hasInited {
		initDefaultConfig()
	}
	return &emptyConfig
}

