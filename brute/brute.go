package brute

import (
	"fmt"
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/cidr"
	"github.com/vela-security/vela-public/lua"
	"gopkg.in/tomb.v2"
	"net"
)

type brute struct {
	lua.LFace
	cfg      *config
	queue    chan Tx
	tom      *tomb.Tomb
	ipskip   map[string]bool
	userskip map[string]bool
}

func newBrute(cfg *config) *brute {
	b := &brute{cfg: cfg}
	return b
}

func (b *brute) Name() string {
	return b.cfg.name
}

func (b *brute) Type() string {
	return typeof
}

func (b *brute) State() lua.ProcState {
	return lua.PTRun
}

func (b *brute) append(s service) {
	b.cfg.service = append(b.cfg.service, s)
}

func (b *brute) succeed(ev *event) {
	e := audit.NewEvent("crackonline success").User(ev.user).Msg("ip:%s user:%s pass:%s port:%d", ev.ip, ev.user, ev.pass, ev.port)
	e.Subject(ev.banner).From(b.cfg.co.CodeVM()).High().Alert()

	b.cfg.pipe.Do(e, b.cfg.co, func(err error) {
		xEnv.Errorf("%s call succeed pipe fail %v", b.Name(), err)
	})
}

func (b *brute) verbose(ev *event) {
	e := audit.NewEvent("crackonline err").User(ev.user).Msg("ip:%s user:%s pass:%s port:%d", ev.ip, ev.user, ev.pass, ev.port)
	e.Subject(ev.banner).From(b.cfg.co.CodeVM()).High()
	b.cfg.pipe.Do(e, b.cfg.co, func(err error) {
		xEnv.Errorf("%s call verbose pipe fail %v", b.Name(), err)
	})
}

func (b *brute) help(s service) func(net.IP) {
	fn := func(ip net.IP) {
		//ip:port是否可达
		if !s.Ping(ip) {
			xEnv.Errorf("IP %v , port: %v can not connectted! ", ip, s.port)
			b.verbose(&event{
				ip:     ip.String(),
				port:   s.port,
				stat:   Unreachable,
				banner: "ip unreachable!",
			})
			return
		}

		//开始遍历字典
		iter := b.cfg.dict.Iterator()
		defer iter.Close()
		for info := iter.Next(); !info.over; info = iter.Next() {
			select {
			case <-b.tom.Dying():
				println("dying")
				return

			default:
				if b.ipskip[ip.String()] == true {
					iter.Skip()
					break
				}
				b.queue <- Tx{ip: ip, info: info, iter: iter, service: s}
			}
		}
	}

	return fn
}

func (b *brute) async() {
	n := len(b.cfg.service)
	if n == 0 {
		return
	}
	for i := 0; i < n; i++ {
		go func(s service) {
			cidr.Visit(b.tom, b.cfg.cidr, b.help(s)) //这里会阻塞
		}(b.cfg.service[i])
	}
}

func (b *brute) Start() error {
	b.tom = new(tomb.Tomb)
	b.queue = make(chan Tx, 2048)
	go b.async()

	for i := 0; i < b.cfg.thread; i++ {
		go b.thread(i)
	}

	return nil
}

func (b *brute) Close() error {
	xEnv.Errorf("close")
	b.tom.Kill(fmt.Errorf("close"))
	close(b.queue)
	return nil
}

func (b *brute) thread(idx int) {
	xEnv.Debugf("b thread %d start", idx)
	defer func() {
		xEnv.Debugf("b thread %d close", idx)
	}()
	for tx := range b.queue {
		ev := &event{
			ip:      tx.ip.String(),
			user:    tx.info.name,
			pass:    tx.info.pass,
			port:    tx.service.port,
			service: tx.service.auth.Name(),
		}
		tx.service.Do(ev)
		switch ev.stat {
		case Succeed:
			b.succeed(ev)
			if tx.service.skip {
				tx.iter.Skip()
				goto done
			}
			//跳过当前用户名
			tx.iter.SkipU()
		case Denied:
			//用户被锁定 跳过
			tx.iter.SkipU()
		case Fail:
		case Unreachable:
			tx.iter.Skip()
		}
	done:
		//b.verbose(ev)
	}

}
