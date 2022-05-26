package brute

import (
	"github.com/22ke/gordp/glog"
	gor "github.com/22ke/gordp/login"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
)

type rdp struct {
}

func newBruteRdp(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &rdp{}
	return newService(L, sv, port)
}

func (r *rdp) Name() string {
	return "rdp"
}

func (r *rdp) Login(ev *event) {
	var err error
	g := gor.NewClient(ev.Server(), glog.NONE)

	err = g.LoginForSSL("", ev.user, ev.pass)
	if err.Error() == "fail" {
		ev.stat = Succeed
		ev.banner = "RDP HIT"
		println("login success , ", ev.ip, ev.user, ev.pass)
		return
	}
	ev.stat = Fail
	ev.banner = "RDP fail"
	//SSL协议登录测试
	//err = g.LoginForRDP("", ev.user, ev.pass)
	//if err == nil {
	//	println(ev.ip, ev.user, ev.pass)
	//	ev.stat = Fail
	//	ev.banner = "fail"
	//	return
	//}

	//println(err.Error())
	//if strings.Contains(err.Error(), "success") {
	//	ev.stat = Succeed
	//	ev.banner = "RDP HIT"
	//	println("login success , ", ev.user, ev.pass)
	//	//o.ev(ip, user, pass, port, "rdp hit")
	//} else {
	//	println(err.Error(), ev.Server(), ev.user, ev.pass)
	//}
}
