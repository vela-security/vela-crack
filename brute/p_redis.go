package brute

import (
	red "github.com/go-redis/redis"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
	"time"
)

type redis struct {
	timeout time.Duration
}

func newBruteRedis(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &redis{
		timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (r *redis) Name() string {
	return "redis"
}

func (r *redis) Login(ev *event) {
	opt := &red.Options{Addr: ev.Server(),
		Password:    ev.pass,
		DB:          0,
		DialTimeout: r.timeout * time.Second}
	client := red.NewClient(opt)
	defer client.Close()
	_, err := client.Ping().Result()
	if err == nil {
		ev.stat = Succeed
		ev.banner = "REDIS HIT"
		println("redis success ", ev.ip, ev.user, ev.pass)
		//println(pass)
		//o.ev(ip, user, pass, port, "redis hit")

	} else {
		ev.stat = Fail
		ev.banner = "REDIS fail"
		//println("reids fail ", err.Error(), ev.ip, ev.user, ev.pass)
		//println(pass,err.Error())
	}
}
