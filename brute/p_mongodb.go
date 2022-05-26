package brute

import (
	"fmt"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
	"gopkg.in/mgo.v2"
	"time"
)

type mongodb struct {
	timeout time.Duration
}

func newBruteMongodb(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &mongodb{
		timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	if sv.timeout == 0 {
		xEnv.Errorf("mongodb timeout not set: %s , default 5", opt.RawGetString("timeout").String())
		sv.timeout = 5 * time.Second
	}
	return newService(L, sv, port)
}

func (m *mongodb) Name() string {
	return "mongodb"
}

func (m *mongodb) Login(ev *event) {
	url := fmt.Sprintf("mongodb://%v:%v@%v/%v", ev.user, ev.pass, ev.Server(), "admin")
	session, err := mgo.DialWithTimeout(url, m.timeout)

	if err == nil {
		defer session.Close()
		err = session.Ping()
		if err == nil {
			ev.stat = Succeed
			ev.banner = "MONGODB HIT!"
			println("success", ev.user, ev.pass)

		} else {
			ev.stat = Fail
			ev.banner = err.Error()
		}
	} else {
		ev.stat = Unreachable
		ev.banner = fmt.Sprintf("connect mongodb err : %s", err.Error())
	}
}
