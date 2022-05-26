package dict

type Than func(string) (over bool)

type Scanner interface {
	Next() bool
	Done()
	Text() string
}

type Dictionary interface {
	Wrap() error
	ForEach(Than) error
	Scanner() Scanner
}
