package john

import (
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"github.com/vela-security/vela-public/worker"
	tomb2 "gopkg.in/tomb.v2"
)

func (j *john) onMatch(h happy) {
	j.cfg.pip.Do(h, j.cfg.co, func(err error) {
		audit.Errorf("crack %s pipe do fail %v", h.method, err).From(j.cfg.co.CodeVM()).High().Put()
	})
}

func (j *john) pipe(L *lua.LState) int {
	j.cfg.pip.CheckMany(L, pipe.Seek(0))
	return 0
}

func (j *john) shadowL(L *lua.LState) int {
	tomb := new(tomb2.Tomb)
	raw := L.IsString(1)
	if raw == "" {
		return 0
	}

	worker.New(L, j.Name()+".worker").Env(xEnv).
		Task(func() { j.shadow(raw, tomb) }).
		Kill(func() { tomb.Kill(nil) }).
		Start()
	return 0
}
func (j *john) md5L(L *lua.LState) int {
	tomb := new(tomb2.Tomb)
	raw := L.IsString(1)
	if raw == "" {
		return 0
	}

	worker.New(L, j.Name()+".worker").Env(xEnv).
		Task(func() { j.md5(raw, tomb) }).
		Kill(func() { tomb.Kill(nil) }).
		Start()
	return 0
}

func (j *john) sha256L(L *lua.LState) int {
	tomb := new(tomb2.Tomb)
	raw := L.IsString(1)
	if raw == "" {
		return 0
	}

	worker.New(L, j.Name()+".worker").Env(xEnv).
		Task(func() { j.sha256(raw, tomb) }).
		Kill(func() { tomb.Kill(nil) }).
		Start()
	return 0
}

func (j *john) sha512L(L *lua.LState) int {
	tomb := new(tomb2.Tomb)
	raw := L.IsString(1)
	if raw == "" {
		return 0
	}

	worker.New(L, j.Name()+".worker").Env(xEnv).
		Task(func() { j.sha512(raw, tomb) }).
		Kill(func() { tomb.Kill(nil) }).
		Start()
	return 0
}

func (j *john) rainbowL(L *lua.LState) int {
	tomb := new(tomb2.Tomb)
	raw := L.IsString(1)
	if raw == "" {
		return 0
	}

	worker.New(L, j.Name()+".worker").Env(xEnv).
		Task(func() { j.rainbow(raw, tomb) }).
		Kill(func() { tomb.Kill(nil) }).
		Start()
	return 0
}

func (j *john) equalL(L *lua.LState) int {
	tomb := new(tomb2.Tomb)
	raw := L.IsString(1)
	if raw == "" {
		return 0
	}

	worker.New(L, j.Name()+".worker").Env(xEnv).
		Task(func() { j.equal(raw, tomb) }).
		Kill(func() { tomb.Kill(nil) }).
		Start()
	return 0
}

func (j *john) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "pipe":
		return lua.NewFunction(j.pipe)

	case "equal":
		return lua.NewFunction(j.equalL)

	case "rainbow":
		return lua.NewFunction(j.rainbowL)

	case "shadow":
		return lua.NewFunction(j.shadowL)

	case "md5":
		return lua.NewFunction(j.md5L)

	case "sha256":
		return lua.NewFunction(j.sha256L)

	case "sha512":
		return lua.NewFunction(j.sha512L)
	}

	return nil
}
