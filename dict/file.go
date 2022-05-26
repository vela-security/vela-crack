package dict

import (
	"bufio"
	"fmt"
	"os"
)

type File struct {
	err      error
	size     int64
	filename string
}

func NewFile(filename string) *File {
	s, err := os.Stat(filename)
	if err != nil {
		return &File{err: err, filename: filename}
	}

	if s.IsDir() {
		return &File{err: fmt.Errorf("dict %s file is dir", filename), filename: filename}
	}

	return &File{
		size:     s.Size(),
		filename: filename,
	}
}

func (f *File) Wrap() error {
	return f.err
}

func (f *File) ForEach(than Than) error {
	fd, err := os.Open(f.filename)
	if err != nil {
		return err
	}
	defer fd.Close()

	scanner := bufio.NewScanner(fd)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		if e := scanner.Err(); e != nil {
			return e
		}

		if than(scanner.Text()) {
			return nil
		}
	}
	return nil
}

func (f *File) Scanner() Scanner {
	fd, err := os.Open(f.filename)
	if err != nil {
		return nil
	}

	sc := bufio.NewScanner(fd)
	sc.Split(bufio.ScanLines)

	return &FileScanner{
		fd:      fd,
		value:   f,
		scanner: sc,
	}

}
