package john

import (
	"github.com/vela-security/vela-crack/dict"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

type config struct {
	speed int
	name  string
	dict  dict.Dictionary
	salt  string

	co  *lua.LState
	pip *pipe.Px
}

func (c config) verify() interface{} {
	return nil
}

func (c *config) setDict(L *lua.LState, val lua.LValue) {
	switch val.Type() {
	case lua.LTTable:
		c.dict = dict.NewMemory(auxlib.LTab2SS(val.(*lua.LTable)))
	case lua.LTString:
		c.dict = dict.NewFile(val.String())

	default:
		L.RaiseError("dict must be file or tab , got %v", val.Type().String())
	}

	if err := c.dict.Wrap(); err != nil {
		L.RaiseError("dict got %v", err)
	}
}

func (c *config) Index(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "name":
		c.name = auxlib.CheckProcName(val, L)

	case "speed":
		c.speed = lua.IsInt(val)

	case "dict":
		c.setDict(L, val)

	case "salt":
		c.salt = lua.IsString(val)

	default:
		L.RaiseError("invalid %s field", key)
		return
	}
}

func newConfig(L *lua.LState) *config {
	val := L.Get(1)
	cfg := &config{
		name: "crack",
		co:   xEnv.Clone(L),
		pip:  pipe.New(),
	}

	switch val.Type() {
	case lua.LTString:
		cfg.name = auxlib.CheckProcName(val, L)

	case lua.LTTable:
		val.(*lua.LTable).Range(func(key string, val lua.LValue) { cfg.Index(L, key, val) })

	default:
		L.RaiseError("invalid config type must string or table , got %s", val.Type().String())
		return nil
	}

	if e := cfg.verify(); e != nil {
		L.RaiseError("%v", e)
		return nil
	}

	return cfg

}
