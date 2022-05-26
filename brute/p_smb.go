package brute

import (
	"github.com/spf13/cast"
	sm "github.com/stacktitan/smb/smb"
	"github.com/vela-security/vela-public/lua"
	"time"
)

type smb struct {
	timeout time.Duration
}

func newBruteSmb(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &smb{
		timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (s *smb) Name() string {
	return "smb"
}

func (s *smb) Login(ev *event) {
	options := sm.Options{
		Host:        ev.ip,
		Port:        ev.port,
		User:        ev.user,
		Password:    ev.pass,
		Domain:      "",
		Workstation: "",
	}

	session, err := sm.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			ev.stat = Succeed
			ev.banner = "SMB HTI!"
			println("SMB HIT ", ev.ip, ev.user, ev.pass)
			return
			//o.ev(ip, user, pass, port, "smb hit")
		}
		ev.stat = Fail
		ev.banner = "SMB fail"
	} else {
		ev.stat = Fail
		ev.banner = "SMB fail"
		//println(pass,err.Error())
	}
}
