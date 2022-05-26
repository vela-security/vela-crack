package brute

import (
	"sync/atomic"
)

type iteratorM struct {
	Super

	object *memory

	uSize uint32
	pSize uint32

	uSeek uint32
	pSeek uint32
}

type memory struct {
	use  []string
	pass []string
}

func (iter *iteratorM) Iterator() Iterator {
	if iter.object == nil {
		return &iteratorM{
			object: nil,
			uSeek:  0,
			pSeek:  0,
			uSize:  0,
			pSize:  0,
		}
	}
	return &iteratorM{
		object: iter.object,
		uSeek:  0,
		pSeek:  0,
		uSize:  uint32(len(iter.object.use)),
		pSize:  uint32(len(iter.object.pass)),
	}
}

func (m *memory) Iterator() *iteratorM {
	return &iteratorM{
		object: m,
		uSeek:  0,
		pSeek:  0,
		uSize:  uint32(len(m.use)),
		pSize:  uint32(len(m.pass)),
	}
}

func (iter *iteratorM) Updatem(m *memory) {
	if iter.object == nil {
		iter.object = m
		return
	}
	if m.use != nil {
		iter.object.use = append(iter.object.use, m.use...)
		iter.uSize = uint32(len(iter.object.use))
		return
	}
	if m.pass != nil {
		iter.object.pass = append(iter.object.pass, m.pass...)
		iter.pSize = uint32(len(iter.object.pass))
		return
	}
}

func (iter *iteratorM) SkipU() {
	atomic.AddUint32(&iter.uSeek, 1)
}

func (iter *iteratorM) Skip() {
	atomic.AddUint32(&iter.uSeek, iter.uSize+1)
}

func (iter *iteratorM) Next() dictEntry {

next:
	if iter.uSeek >= iter.uSize {
		return dictEntry{over: true}
	}
	if iter.pSeek < iter.pSize {
		iter.pSeek = atomic.AddUint32(&iter.pSeek, 1)
		return dictEntry{
			name: iter.object.use[iter.uSeek],
			pass: iter.object.pass[iter.pSeek-1],
			over: false,
		}
	}

	if iter.pSeek == iter.pSize {
		iter.uSeek = atomic.AddUint32(&iter.uSeek, 1)
		iter.pSeek = uint32(0)
	}

	goto next
}

func (iter *iteratorM) Close() error {
	iter.Skip()
	return nil
}
