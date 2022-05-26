package brute

import (
	"github.com/spf13/cast"
	"github.com/vela-security/vela-public/lua"
	"gopkg.in/olivere/elastic.v3"
)

type Elastic struct {
	scheme string
}

func (ec *Elastic) Name() string {
	return "elastic"
}

func newBruteElastic(L *lua.LState) service {
	val := L.CheckTable(1)
	port := cast.ToInt(val.RawGetString("port").String())
	scheme := val.RawGetString("scheme").String()
	if scheme == "" {
		scheme = "http"
	}
	e := &Elastic{scheme: scheme}
	return newService(L, e, port)
}

func (ec *Elastic) Login(ev *event) {
	_, err := elastic.NewClient(elastic.SetURL(ec.scheme+"://"+ev.Server()),
		elastic.SetSniff(false),
		elastic.SetBasicAuth(ev.user, ev.pass),
	)

	if err == nil {
		ev.stat = Succeed
		ev.banner = "ELASTIC"
		println("success: ", ev.user, ev.pass)
	} else {
		ev.stat = Fail
		ev.banner = err.Error()
	}
}
