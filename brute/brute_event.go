package brute

import (
	"github.com/vela-security/vela-public/lua"
	"strconv"
)

type event struct {
	ip      string
	port    int
	user    string
	pass    string
	stat    State
	service string
	banner  string
}

func (ev *event) ToLValue() lua.LValue {
	return lua.NewAnyData(&ev)
}

func (ev *event) Server() string {
	return ev.ip + ":" + strconv.Itoa(ev.port)
}
