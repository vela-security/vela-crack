package brute

import (
	"database/sql"
	"fmt"
	_ "github.com/netxfly/mysql"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
)

type mysql struct {
}

func newBruteMysql(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &mysql{
		//timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (m *mysql) Name() string {
	return "mysql"
}

func (m *mysql) Login(ev *event) {
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8", ev.user, ev.pass, ev.ip, ev.port, "mysql")
	//fmt.Printf("mysql login user:%v,pass:%v\n", ev.user, ev.pass)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		defer db.Close()
		err = db.Ping()
		if err == nil {
			ev.stat = Succeed
			ev.banner = "MYSQL HIT!"
			xEnv.Error("success :", ev.user, ev.pass)
			return
			//o.ev(ip, user, pass, port, "mysql hit")

		}
		ev.stat = Fail
		ev.banner = err.Error()
	}
	//ip有问题
}
