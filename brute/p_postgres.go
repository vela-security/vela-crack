package brute

import (
	"database/sql"
	"fmt"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
)

type postgres struct {
}

func newBrutePostgres(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &postgres{
		//timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (p *postgres) Name() string {
	return "postgres"
}

func (p *postgres) Login(ev *event) {
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
