package dict

type Memory struct {
	value []string
}

func NewMemory(v []string) *Memory {
	return &Memory{value: v}
}

func (mem *Memory) Wrap() error {
	return nil
}

func (mem *Memory) ForEach(than Than) error {
	n := len(mem.value)
	if n == 0 {
		return nil
	}

	for i := 0; i < n; i++ {
		if than(mem.value[i]) {
			return nil
		}
	}

	return nil
}

func (mem *Memory) Scanner() Scanner {
	return &MemoryScanner{size: int32(len(mem.value)), mem: mem, offset: 0}
}
