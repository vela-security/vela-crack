package dict

import "sync/atomic"

type MemoryScanner struct {
	size   int32
	offset int32
	mem    *Memory
}

func (ms *MemoryScanner) Next() bool {
	return atomic.AddInt32(&ms.offset, 1) <= ms.size
}

func (ms *MemoryScanner) Text() string {
	if ms.size == 0 {
		return ""
	}

	if ms.offset == 0 {
		return ms.mem.value[ms.offset]
	}

	if ms.offset > ms.size {
		return ""
	}

	return ms.mem.value[ms.offset-1]
}

func (ms *MemoryScanner) Done() {
	atomic.StoreInt32(&ms.offset, ms.size)
}
