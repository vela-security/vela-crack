package brute

import (
	"bufio"
	"errors"
	"github.com/vela-security/vela-public/auxlib"
	"io"
	"os"
)

type iteratorM2 struct {
	Super
	filem *fileM

	uinit *bufio.Reader
	pinit *bufio.Reader

	u *bufio.Reader
	p *bufio.Reader

	size  int
	uFile *os.File
	pFile *os.File

	name string
	pass string

	ue error
	pe error
}

type fileM struct {
	userf string
	passf string
}

func (iter *iteratorM2) Updatef(filem *fileM) {
	if iter.filem == nil {
		iter.filem = filem
		goto end
	}
	if filem.userf != "" {
		iter.filem.userf = filem.userf
	}
	if filem.passf != "" {
		iter.filem.passf = filem.passf
	}
end:
	iter.Iterator()

}

func (f *fileM) Iterator() *iteratorM2 {
	return &iteratorM2{
		u: nil,
		p: nil,

		uinit: nil,
		pinit: nil,

		ue: errors.New("init"),
		pe: errors.New("init"),

		size:  10240,
		uFile: nil,
		pFile: nil,
		filem: f,
	}
}

func (iter *iteratorM2) Iterator() Iterator {
	if iter.uFile != nil && iter.ue == nil {
		goto pp
	}

	iter.uFile, iter.ue = os.Open(iter.filem.userf)
	if iter.ue == nil {
		stat, _ := iter.uFile.Stat()
		iter.u = bufio.NewReaderSize(iter.uFile, int(stat.Size())+1024)
		iter.ru()
	} else {
		iter.uFile = nil
		iter.uFile.Close()
	}

pp:
	if iter.pFile != nil && iter.pe == nil {
		goto end
	}

	iter.pFile, iter.pe = os.Open(iter.filem.passf)
	if iter.pe == nil {
		stat, _ := iter.pFile.Stat()
		iter.p = bufio.NewReaderSize(iter.pFile, int(stat.Size())+1024)
	} else {
		iter.pFile = nil
		iter.pFile.Close()
	}

end:
	return iter
}

func (iter *iteratorM2) restp() {
	iter.pFile, iter.pe = os.Open(iter.filem.passf)
	if iter.pe == nil {
		stat, _ := iter.pFile.Stat()
		iter.p = bufio.NewReaderSize(iter.pFile, int(stat.Size())+1024)
	} else {
		iter.pFile = nil
		iter.pFile.Close()
	}
}

func (iter *iteratorM2) ru() error {
	if iter.u == nil || iter.ue != nil {
		return iter.ue
	}

	name, err := iter.u.ReadBytes('\n')
	if err == nil {
		iter.name = auxlib.B2S(name[0 : len(name)-2])
		return nil
	}

	iter.ue = err
	return err
}

func (iter *iteratorM2) rp() error {
	if iter.p == nil || iter.pe != nil {
		return iter.pe
	}

	pass, err := iter.p.ReadBytes('\n')
	if err == nil {
		iter.pass = auxlib.B2S(pass[0 : len(pass)-2])
		return nil
	}

	iter.pe = err
	return err
}

func (iter *iteratorM2) SkipU() {
	iter.ru()
	iter.p = nil
	iter.pFile.Close()
	iter.restp()
}

func (iter *iteratorM2) Skip() {
	iter.ue = io.EOF
	iter.pe = io.EOF
	iter.name = ""
	iter.pass = ""
}

func (iter *iteratorM2) Next() dictEntry {
next:
	if iter.ue != nil {
		return dictEntry{over: true}
	}

	err := iter.rp()
	if err == nil {
		return dictEntry{name: iter.name, pass: iter.pass, over: false}
	}

	if err == io.EOF {
		//下一个用户名
		iter.ru()
		iter.p = nil
		iter.pFile.Close()
		iter.restp()

		goto next
	}

	iter.pe = err
	return dictEntry{over: true}
}

func (iter *iteratorM2) Close() error {
	iter.Skip()

	if iter.uFile != nil {
		iter.uFile.Close()
	}

	if iter.pFile != nil {
		iter.pFile.Close()
	}
	return nil
}
