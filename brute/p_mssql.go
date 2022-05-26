package brute

import (
	"database/sql"
	"fmt"
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
)

type mssql struct {
}

func (m *mssql) Name() string {
	return "mssql"
}

func newBruteMssql(L *lua.LState) service {
	opt := L.CheckTable(1)
	port := cast.ToInt(opt.RawGetString("port").String())

	sv := &mssql{
		//timeout: time.Duration(cast.ToInt(opt.RawGetString("timeout").String())),
	}
	return newService(L, sv, port)
}

func (m *mssql) Login(ev *event) {
	dataSourceName := fmt.Sprintf("server=%v;port=%v;user id=%v;password=%v;database=%v", ev.ip, ev.port, ev.user, ev.pass, "master")

	db, err := sql.Open("mssql", dataSourceName)
	if err == nil {
		defer db.Close()
		err = db.Ping()
		if err == nil {
			//o.ev(ip, user, pass, port, "mssql hit")
		}
	} else {
	}
}
