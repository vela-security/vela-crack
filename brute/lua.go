package brute

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
	"reflect"
)

var xEnv assert.Environment

var typeof = reflect.TypeOf((*brute)(nil)).String()

/*
local function handle(ev)
  vela.Debug("crack %v" , ev)
end
local b = crack.brute("crack").Use("C:\\Users\\keke\\Desktop\\userlist.txt").Pass("C:\\Users\\keke\\Desktop\\easypass.txt")
b = b.cidr("172.31.61.199-204").pipe(handle)
-- b.ssh{
--   port = 22,
--   timeout = 1,
-- }
-- b.mysql{
--   port = 3306
-- }
-- b.ftp{
--   port = 21
-- }
-- b.elastic{
--   scheme = "http",
--   port = 9200
-- }
-- b.mongodb{
--   port = 27017,
-- }
-- b.rdp{
--   port = 3389,
-- }
-- b.redis{
--   port = 6379,
--   timeout = 1,
-- }
-- b.smb{
--   port = 445,
--   timeout = 1,
-- }
-- b.smtp{
--   port = 25,
--   timeout = 1,
-- }
-- b.snmp{
--   port = 161,
--   timeout = 1,
-- }
b.web{
  method = "POST",
  url = "https://security.eastmoney.com/srclogin/Home/SubmitLogin",
  query = "userName={user}&password={pass}&hidUrl=",
  contenttype = "application/x-www-form-urlencoded; charset=UTF-8",
  proxy = "http://127.0.0.1:8080",
  checkstatus = 200,
  checkstr = "administrator",
  timeout = 1,
}

b.start()
*/

func BruteL(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, typeof)
	if proc.IsNil() {
		proc.Set(newBrute(cfg))

	} else {
		obj := proc.Data.(*brute)
		xEnv.Free(obj.cfg.co)
		obj.cfg = cfg
	}
	L.Push(proc)

	return 1
}

func WithEnv(env assert.Environment, kv lua.UserKV) {
	xEnv = env
	kv.Set("brute", lua.NewFunction(BruteL))
}
