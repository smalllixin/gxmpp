package gxmpp

type TestServer struct {
	AuthProvider
}

func (s *TestServer) GetUserPassword(username string) string {
	if username == "test" {
		return "999888"
	}
	return "123456"
}