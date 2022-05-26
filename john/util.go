package john

import "strings"

func rainbowDictParse(text string) (hash string, plain string) {
	n := strings.IndexByte(text, ' ')
	if n == -1 {
		hash = text
		return
	}

	if n == len(text)-1 {
		hash = text[:n]
		return
	}

	hash = text[:n]
	plain = text[n+1:]
	return
}
