package gxmpp

import (
)

type AuthProvider interface {
	func GetUserPassword(username) (string, error)
}

