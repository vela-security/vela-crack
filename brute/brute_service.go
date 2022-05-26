package brute

import (
	"github.com/vela-security/vela-public/lua"
	"net"
	"strconv"
	"time"
)

type Authenticate interface {
	Name() string
	Login(*event)
	//Index(*lua.LState , string) lua.LValue
}

type service struct {
	Super
	skip bool
	port int
	ping bool
	auth Authenticate
}

func newService(L *lua.LState, auth Authenticate, port int) service {
	if port > 65535 || port <= 0 {
		L.RaiseError("invalid port %d", port)
		return service{}
	}

	return service{
		port: port,
		skip: true,
		ping: true,
		auth: auth,
	}
}

func (s *service) Ping(ip net.IP) bool {
	if !s.ping {
		return true
	}

	//写ping逻辑
	host := ip.String() + ":" + strconv.Itoa(s.port)
	var d net.Dialer
	d.Timeout = time.Duration(3) * time.Second
	_, err := d.Dial("tcp", host)
	if err != nil {
		return false
	}

	return true
}

func (s *service) Do(ev *event) {
	s.auth.Login(ev)
}
