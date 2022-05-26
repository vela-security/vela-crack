package crack

import (
	"github.com/vela-security/vela-crack/brute"
	"github.com/vela-security/vela-crack/john"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func WithEnv(env assert.Environment) {
	xEnv = env
	kv := lua.NewUserKV()
	//xEnv.Set("john", lua.NewFunction(john.NewLuaCrackJohn))
	//xEnv.Set("brute", lua.NewFunction(brute.BruteL))
	//xEnv.Global()
	john.WithEnv(env, kv)
	brute.WithEnv(env, kv)
	xEnv.Set("crack", kv)
}
