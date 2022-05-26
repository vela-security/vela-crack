package brute

import (
	"bufio"
	"github.com/vela-security/vela-public/cidr"
	"github.com/vela-security/vela-public/lua"
	"os"
	"strconv"
)

func (b *brute) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "use":
		return lua.NewFunction(b.useL)

	case "thread":
		return lua.NewFunction(b.threadL)

	case "pass":
		return lua.NewFunction(b.passL)

	case "Use":
		return lua.NewFunction(b.useFL)

	case "Pass":
		return lua.NewFunction(b.passFL)

	case "cidr":
		return lua.NewFunction(b.cidrL)

	case "Cidr":
		return lua.NewFunction(b.cidrFL)

	case "host":
		return lua.NewFunction(b.hostL)

	case "start":
		return lua.NewFunction(b.startL)

	case "ssh":
		return lua.NewFunction(b.sshL)

	case "elastic":
		return lua.NewFunction(b.elasticL)

	case "ftp":
		return lua.NewFunction(b.ftpL)

	case "mongodb":
		return lua.NewFunction(b.mongodbL)

	case "mssql":
		return lua.NewFunction(b.mssqlL)

	case "mysql":
		return lua.NewFunction(b.mysqlL)

	case "pipe":
		return lua.NewFunction(b.pipeL)

	case "oracle":
		return lua.NewFunction(b.oracleL)

	case "postgres":
		return lua.NewFunction(b.postgresL)

	case "rdp":
		return lua.NewFunction(b.rdpL)

	case "redis":
		return lua.NewFunction(b.redisL)

	case "smb":
		return lua.NewFunction(b.smbL)

	case "smtp":
		return lua.NewFunction(b.smtpL)

	case "snmp":
		return lua.NewFunction(b.snmpL)

	case "web":
		return lua.NewFunction(b.webL)

	default:
		xEnv.Errorf("unknown key : ", key)

	}

	return nil
}

func (b *brute) ret(L *lua.LState) int {
	d := L.NewProcData(b)
	L.Push(d)
	return 1
}

func (b *brute) checkVM(L *lua.LState) bool {
	cu, nu := b.cfg.co.CodeVM(), L.CodeVM()
	if cu != nu {
		L.RaiseError("%s proc start must be %s , but %s", b.Name(), cu, nu)
		return false
	}
	return true
}

func (b *brute) useL(L *lua.LState) int {
	n := L.GetTop()
	m := &memory{}
	for i := 1; i <= n; i++ {
		m.use = append(m.use, L.Get(i).String())
	}
	if b.cfg.dict == nil {
		b.cfg.dict = m.Iterator()
	} else {
		b.cfg.dict.Iterator().UpdateMemory(m)
	}

	return b.ret(L)
}

func (b *brute) useFL(L *lua.LState) int {
	userp := L.Get(1).String()
	if !b.checkfile(userp) {
		xEnv.Errorf("error! open file :%v  error.", userp)
		return b.ret(L)
	}
	m := &fileM{
		userf: "",
		passf: "",
	}
	m.userf = userp
	if b.cfg.dict == nil {
		b.cfg.dict = m.Iterator()
	} else {
		b.cfg.dict.Iterator().UpdateFile(m)
	}
	return b.ret(L)
}

func (b *brute) threadL(L *lua.LState) int {
	ns := L.Get(1).String()
	n, e := strconv.Atoi(ns)
	if e != nil {
		xEnv.Errorf("thread error: ", e.Error())
		b.ret(L)
	}
	b.cfg.thread = n
	b.ret(L)
	return 1
}

func (b *brute) passL(L *lua.LState) int {
	n := L.GetTop()

	m := &memory{}

	for i := 1; i <= n; i++ {
		m.pass = append(m.pass, L.Get(i).String())
	}
	if b.cfg.dict == nil {
		b.cfg.dict = m.Iterator()
	} else {
		b.cfg.dict.Iterator().UpdateMemory(m)
	}
	//b.cfg.dict = m.Iterator()
	return b.ret(L)
}

func (b *brute) passFL(L *lua.LState) int {
	passp := L.Get(1).String()
	if !b.checkfile(passp) {
		xEnv.Errorf("open pass file :%v  error.", passp)
		return b.ret(L)
	}
	m := &fileM{
		userf: "",
		passf: "",
	}
	m.passf = passp
	if b.cfg.dict == nil {
		b.cfg.dict = m.Iterator()
	} else {
		b.cfg.dict.Iterator().UpdateFile(m)
	}

	return b.ret(L)
}

func (b *brute) checkfile(userf string) bool {
	f, e := os.Open(userf)
	defer f.Close()
	if e != nil {
		return false
	} else {
		return true
	}
}

func (b *brute) cidrL(L *lua.LState) int {
	b.cfg.cidr = cidr.Check(L)
	return b.ret(L)
}

func (b *brute) cidrFL(L *lua.LState) int {
	cidrp := L.Get(1).String()
	var c string
	f, e := os.Open(cidrp)
	if e != nil {
		xEnv.Errorf("error! open cidr file :%s  error.", cidrp)
		return b.ret(L)
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		c = s.Text()
		t, e := cidr.Parse(c)
		if e != nil {
			xEnv.Errorf("error! cidr file contant  :%s  error : %s", c, e.Error())
		}
		b.cfg.cidr = append(b.cfg.cidr, t)
	}
	return b.ret(L)
}

func (b *brute) hostL(L *lua.LState) int {
	return 0
}

func (b *brute) startL(L *lua.LState) int {
	b.Start()
	return 0
}

func (b *brute) pipeL(L *lua.LState) int {
	b.cfg.pipe.LValue(L.Get(1))
	return b.ret(L)
}

//******************************************
//----------------协议处理--------------------
//******************************************

func (b *brute) mongodbL(L *lua.LState) int {
	b.append(newBruteMongodb(L))
	return b.ret(L)
}

func (b *brute) mssqlL(L *lua.LState) int {
	b.append(newBruteMssql(L))
	return b.ret(L)
}

func (b *brute) mysqlL(L *lua.LState) int {
	b.append(newBruteMysql(L))
	return b.ret(L)
}

func (b *brute) oracleL(L *lua.LState) int {
	b.append(newBruteOracle(L))
	return b.ret(L)
}

func (b *brute) postgresL(L *lua.LState) int {
	b.append(newBrutePostgres(L))
	return b.ret(L)
}

func (b *brute) rdpL(L *lua.LState) int {
	b.append(newBruteRdp(L))
	return b.ret(L)
}

func (b *brute) redisL(L *lua.LState) int {
	b.append(newBruteRedis(L))
	return b.ret(L)
}

func (b *brute) smbL(L *lua.LState) int {
	b.append(newBruteSmb(L))
	return b.ret(L)
}

func (b *brute) smtpL(L *lua.LState) int {
	b.append(newBruteSmtp(L))
	return b.ret(L)
}

func (b *brute) snmpL(L *lua.LState) int {
	b.append(newBruteSnmp(L))
	return b.ret(L)
}

func (b *brute) webL(L *lua.LState) int {
	b.append(newBruteWeb(L))
	return b.ret(L)
}

func (b *brute) sshL(L *lua.LState) int {
	s := newBruteSsh(L)
	b.append(s)
	return b.ret(L)
}

func (b *brute) ftpL(L *lua.LState) int {
	b.append(newBruteFtp(L))
	return b.ret(L)
}

func (b *brute) elasticL(L *lua.LState) int {
	b.append(newBruteElastic(L))
	return b.ret(L)
}
