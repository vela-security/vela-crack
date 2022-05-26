package john

import (
	"github.com/vela-security/vela-public/kind"
	"github.com/vela-security/vela-public/lua"
)

type happy struct {
	method string
	user   string
	pass   string
	cipher string
}

func (hy happy) String() string                         { return lua.B2S(hy.Byte()) }
func (hy happy) Type() lua.LValueType                   { return lua.LTObject }
func (hy happy) AssertFloat64() (float64, bool)         { return 0, false }
func (hy happy) AssertString() (string, bool)           { return "", false }
func (hy happy) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (hy happy) Peek() lua.LValue                       { return hy }

func (hy happy) Byte() []byte {
	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.KV("cipher", hy.cipher)
	enc.KV("pass", hy.pass)
	enc.KV("user", hy.user)
	enc.End("}")
	return enc.Bytes()
}
