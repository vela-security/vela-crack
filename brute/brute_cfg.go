package brute

import (
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/cidr"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

type config struct {
	name string
	//limit  int
	thread int
	dict   Dict
	co     *lua.LState

	pipe *pipe.Px

	cidr    []*cidr.T
	service []service
}

func (c config) verify() error {
	return nil
}

func (c *config) Index(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "name":
		c.name = auxlib.CheckProcName(val, L)
	case "server":
		c.service = append(c.service)

	default:
		L.RaiseError("invalid %s field", key)
		return
	}
}

func newConfig(L *lua.LState) *config {
	val := L.Get(1)
	cfg := &config{
		pipe:   pipe.New(),
		thread: 10, //default
		co:     xEnv.Clone(L),
	}

	switch val.Type() {
	case lua.LTString:
		cfg.name = auxlib.CheckProcName(val, L)

	case lua.LTTable:
		val.(*lua.LTable).Range(func(key string, val lua.LValue) { cfg.Index(L, key, val) })

	default:
		L.RaiseError("not found field")
		return nil
	}

	if e := cfg.verify(); e != nil {
		L.RaiseError("%v", e)
		return nil
	}
	return cfg
}
