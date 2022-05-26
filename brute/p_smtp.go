package brute

import (
	"crypto/tls"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
	sm "net/smtp"
	"strings"
)

type smtp struct {
}

func newBruteSmtp(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &smtp{}
	return newService(L, sv, port)
}

func (s *smtp) Name() string {
	return "smtp"
}
func (s *smtp) Login(ev *event) {
	str := ev.Server()
	c, err := sm.Dial(str)
	if err != nil {
		//println("dial",err.Error())
		xEnv.Errorf("dial %s err : %s", ev.ip, err.Error())
		return
	}
	auth := sm.PlainAuth("", ev.user, ev.pass, ev.ip)

	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{ServerName: ev.ip, InsecureSkipVerify: true}
		if err = c.StartTLS(config); err != nil {
			//println("call start tls")
			//return err
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(auth); err != nil {
				if strings.Contains(err.Error(), "504 Unrecognized authentication type") {
					xEnv.Errorf("smtp crack error: 线程数量过多！ %s", err.Error())
					return
				}
				//xEnv.Errorf("smtp crack error:  %s,%s,%s,%s", err.Error(), ev.ip, ev.user, ev.pass)
				//密码错误
			} else {
				ev.stat = Succeed
				ev.banner = "SMTP HIT"
				println("SMTP HIT ", ev.ip, ev.user, ev.pass)
				return
				//println(user,pass)
				//o.ev(ip, user, pass, port, "smtp hit")
			}
		}

	}
}
