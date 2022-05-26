package brute

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
	"strings"
	"time"
)

type Ftp struct {
	timeout time.Duration
}

func newBruteFtp(L *lua.LState) service {
	val := L.CheckTable(1)
	port := cast.ToInt(val.RawGetString("port").String())

	e := &Ftp{
		timeout: time.Duration(cast.ToInt(val.RawGetString("timeout").String())),
	}
	if e.timeout == 0 {
		xEnv.Errorf("ftp timeout not set: %s , default 5", val.RawGetString("timeout").String())
		e.timeout = 5 * time.Second
	}

	//println("timeout: ", e.timeout)
	return newService(L, e, port)
}

func (f *Ftp) Name() string {
	return "ftp"
}

func (f *Ftp) Login(ev *event) {
	conn, err := ftp.DialTimeout(ev.Server(), f.timeout)

	if err != nil {
		ev.stat = Fail
		ev.banner = err.Error()
		return
	}

	err = conn.Login(ev.user, ev.pass)
	if err != nil {
		//println("fail \n", ev.user,ev.pass)
		ev.banner = err.Error()
		if strings.Contains(ev.banner, "Permission denied") {
			ev.stat = Denied
			ev.banner = fmt.Sprintf("FTP IP:%s,User:%s denied!", ev.ip, ev.pass)
		} else {
			ev.stat = Fail
			ev.banner = fmt.Sprintf("FTP IP:%s,User:%s denied!", ev.ip, ev.pass)
		}
		return
	}
	defer conn.Logout()

	ev.stat = Succeed
	ev.banner = "FTP!"
	println("success ", ev.user, ev.pass)
}
