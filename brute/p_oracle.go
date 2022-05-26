package brute

import (
	"database/sql"
	"fmt"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
)

type oracle struct {
}

func newBruteOracle(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &oracle{
		//timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (o *oracle) Name() string {
	return "oracle"
}

func (o *oracle) Login(ev *event) {
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", ev.user,
		ev.pass, ev.ip, ev.port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)

	if err == nil {
		defer db.Close()
		err = db.Ping()
		if err == nil {
			//o.ev(ip, user, pass, port, "mysql hit")
		}
	}
}
