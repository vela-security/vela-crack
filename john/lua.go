package john

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

/*
	local function handle(ev)
		ev.Put(true , true)
	end


	local john = crack.john{
		name = "shadow",
		dict = "share/dict/pass.dict",
		pipe = handle
	}

	local john = crack.john("shadow")
         .dict("share/dict/pass.dict")
         .pipe(handle)

	john.pipe(_(ev) std.out.println(tostring(ev) ) end)

	john.shadow("$1$xxx")
	john.md5("xxxx")
	john.sha256("xxx")
	john.sha512("xxxxxx")

*/

func NewLuaCrackJohn(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, fileTypeOf)
	if proc.IsNil() {
		proc.Set(newJohn(cfg))

	} else {
		old := proc.Data.(*john)
		xEnv.Free(old.cfg.co)
		old.cfg = cfg
	}
	L.Push(proc)
	return 1
}

func WithEnv(env assert.Environment, kv lua.UserKV) {
	xEnv = env
	kv.Set("john", lua.NewFunction(NewLuaCrackJohn))
}
