package john

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/tredoe/osutil/user/crypt"
	"github.com/tredoe/osutil/user/crypt/md5_crypt"
	"github.com/tredoe/osutil/user/crypt/sha256_crypt"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
	"github.com/vela-security/vela-chameleon/vitess/go/vt/log"
	"github.com/vela-security/vela-public/lua"
	"hash"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	MD5 uint8 = iota + 1
	EQUAL
	RAINBOW
	SHA256
	SHA512
	SHADOW
)

var fileTypeOf = reflect.TypeOf((*john)(nil)).String()

type john struct {
	lua.ProcEx
	cfg *config
}

func newJohn(cfg *config) *john {
	obj := &john{cfg: cfg}
	obj.V(lua.PTInit, time.Now())
	return obj
}

func (j *john) Start() error {
	return nil
}

func (j *john) Close() error {
	return nil
}

func (j *john) ret(L *lua.LState) int {
	L.Push(L.NewProcData(j))
	return 1
}

func (j *john) compareVM(co1 *lua.LState, co2 *lua.LState) bool {
	if co1 == nil || co2 == nil {
		return false
	}

	vm1 := co1.CodeVM()
	vm2 := co2.CodeVM()

	if vm1 == "" || vm2 == "" {
		return false
	}

	return vm1 == vm2
}

func (j *john) shadow(raw string) {
	//1. 首先解析shadow raw 字符串
	//2. 开始爆破
	//3. 命中后运行pipe中的逻辑
	/*4.
	ev := audit.NewEvent("john").User(u).Msg("hash:%s pass:%s" , hash , pass)
	j.call(ev)
	*/
	//root:$6$X7Z9HGT8$.810fZP6mWm19PKSboWRLqCjGFyrH5doETlIqfPiPxQtCKFH2ecvG/xxtMdzE0pJG.amPTz5W/21/kJQ0O3Wl0:18896:0:99999:7:::

	//获取加密方式
	passtype := strings.Split(raw, "$")
	if len(passtype) < 4 {
		return
	}
	salt := "$" + passtype[1] + "$" + passtype[2] + "$"
	tp := passtype[1]

	t, err := strconv.Atoi(tp)
	if err != nil {
		log.Errorf("shadow type to int error : ", err)
	}
	var cryp crypt.Crypter
	switch t {
	case 1:
		cryp = md5_crypt.New()
	case 5:
		cryp = sha256_crypt.New()
	case 6:
		cryp = sha512_crypt.New()
	default:
		log.Errorf("crypto new nil")
		//panic("nil cryp")
	}
	//获取加密shadow
	passhash := strings.Split(raw, ":")
	if len(passhash) < 4 {
		log.Errorf("length sahdow err")
		//panic("length shadow err")
	}
	user := passhash[0]
	hashedpass := passhash[1]

	//将密码字典进行加密并比较
	err, ok, plain := j.Shadow(cryp, hashedpass, salt)
	if err != nil {
		log.Errorf("checkshadow err : ", err)
		xEnv.Infof("shadow parse fail %v", err)
		return
		//panic(err)
	}

	if !ok {
		return
	}

	j.onMatch(happy{
		method: "shadow",
		user:   user,
		pass:   plain,
		cipher: raw,
	})
}

func (j *john) Shadow(crypt crypt.Crypter, hashedpass string, salt string) (error, bool, string) {

	if j.cfg.dict == nil {
		return fmt.Errorf("not found dictionary"), false, ""
	}

	scan := j.cfg.dict.Scanner()
	sa := lua.S2B(salt)

	for scan.Next() {
		raw := scan.Text()
		ph, err := crypt.Generate(lua.S2B(raw), sa)
		if err != nil {
			xEnv.Errorf("crypt %s fail %v", raw, err)
			continue
		}

		if ph != hashedpass {
			continue
		}

		scan.Done()
		return nil, true, raw
	}

	return nil, false, ""
}

func (j *john) Crypt(h hash.Hash, raw string) (bool, string) {
	if j.cfg.dict == nil {
		return false, ""
	}

	scan := j.cfg.dict.Scanner()
	salt := lua.S2B(j.cfg.salt)

	for scan.Next() {
		text := lua.S2B(scan.Text())
		text = append(text, salt...)

		_, err := h.Write(text)
		if err != nil {
			xEnv.Errorf("crypt %s fail %v", raw, err)
			continue
		}

		if hex.EncodeToString(h.Sum(nil)) == raw {
			scan.Done()
			return true, lua.B2S(text)
		}
		h.Reset()
	}

	return false, ""
}

func (j *john) checkcryptstr(h hash.Hash, src string, raw string) (bool, string) {
	salt := j.cfg.salt
	h.Write([]byte(src))
	if len(salt) != 0 {
		h.Write([]byte(salt))
	}
	if fmt.Sprintf("%x", h.Sum(nil)) == raw {
		h.Reset()
		return true, src
	}
	h.Reset()
	return false, ""
}

func (j *john) md5(raw string) { //raw : eeda50edb56d...
	h := md5.New()
	ok, plain := j.Crypt(h, raw)
	if !ok {
		return
	}

	j.onMatch(happy{
		method: "md5",
		pass:   plain,
		cipher: raw,
	})
}

func (j *john) sha256(raw string) {
	h := sha256.New()
	ok, plain := j.Crypt(h, raw)
	if !ok {
		return
	}

	j.onMatch(happy{
		method: "sha256",
		pass:   plain,
		cipher: raw,
	})
}

func (j *john) sha512(raw string) {
	h := sha512.New()
	ok, plain := j.Crypt(h, raw)
	if !ok {
		return
	}

	j.onMatch(happy{
		method: "sha512",
		pass:   plain,
		cipher: raw,
	})
}

func (j *john) rainbow(raw string) {
	if j.cfg.dict == nil {
		return
	}

	scan := j.cfg.dict.Scanner()

	for scan.Next() {
		text := scan.Text()
		hash, plain := rainbowDictParse(text)
		if hash == raw {
			scan.Done()
			j.onMatch(happy{
				method: "rainbow",
				pass:   plain,
				cipher: raw,
			})
			return
		}
	}
}

func (j *john) equal(raw string) {
	if j.cfg.dict == nil {
		return
	}

	scan := j.cfg.dict.Scanner()
	for scan.Next() {
		text := scan.Text()
		if text == raw {
			scan.Done()
			j.onMatch(happy{
				method: "equal",
				pass:   text,
				cipher: raw,
			})
			return
		}
	}
}

func (j *john) dict(L *lua.LState) int {
	//1. 判断是ext 后缀是否为 txt dict 等文件路径
	//2. 如果是文件 运行时打开io
	//3. 如果是文本 运行是 strings.NewReader("xxxxx")
	return j.ret(L)
}

func (j *john) attack(method uint8, raw string) {
	if raw == "" {
		return
	}

	//hash方式  $pass$salt
	switch method {
	case MD5:
		j.md5(raw)
	case SHA256:
		j.sha256(raw)
	case SHA512:
		j.sha512(raw)
	case SHADOW:
		j.shadow(raw)

	case EQUAL:
		j.equal(raw)

	case RAINBOW:
		j.rainbow(raw)
	}
}
