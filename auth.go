package gxmpp

import (
)

type AuthProvider interface {
	GetUserPassword(username string) (string, error)
	//authcid usually is username[authentication]. authzid is [authorization id]
	Authorize(authcid, authzid string) (bool, error)
}

