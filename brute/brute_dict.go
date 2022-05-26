package brute

type dictEntry struct {
	name string
	pass string
	over bool
}

type Iterator interface {
	SkipU() //stop user
	Skip()  //stop
	Next() dictEntry
	Close() error
	UpdateMemory(*memory)
	UpdateFile(*fileM)
}

type Dict interface {
	Iterator() Iterator
}

type Super struct{}

func (su *Super) UpdateMemory(*memory) {}
func (su *Super) UpdateFile(*fileM)    {}
