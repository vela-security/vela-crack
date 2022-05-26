package dict

import (
	"bufio"
	"io"
	"sync/atomic"
)

type FileScanner struct {
	done    uint32
	fd      io.ReadCloser
	value   *File
	scanner *bufio.Scanner
}

func (fs *FileScanner) Next() bool {
	if atomic.LoadUint32(&fs.done) != 0 {
		return false
	}
	return fs.scanner.Scan()
}

func (fs *FileScanner) Done() {
	atomic.StoreUint32(&fs.done, 1)
	if fs.fd != nil {
		fs.fd.Close()
		fs.fd = nil
	}
}

func (fs *FileScanner) Text() string {
	if atomic.LoadUint32(&fs.done) != 0 {
		return ""
	}
	if fs.fd == nil {
		return ""
	}

	return fs.scanner.Text()
}
