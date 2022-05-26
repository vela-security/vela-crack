package brute

import "net"

const (
	Succeed State = iota + 1
	Fail
	Unreachable
	Denied
)

type State uint8

type Tx struct {
	ip      net.IP
	info    dictEntry
	service service
	iter    Iterator
}
