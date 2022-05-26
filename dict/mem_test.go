package dict

import (
	"testing"
	"time"
)

func TestMemory(t *testing.T) {
	m := Memory{value: []string{"admin", "passwd", "baidu", "yes", "sorry", "happy", "cc", "bb", "dd", "EE", "ff", "GG"}}
	scan := m.Scanner()
	for scan.Next() {
		t.Logf("id:1 text:%s", scan.Text())
	}

}

func TestMemory_Scanner(t *testing.T) {
	m := Memory{value: []string{"admin", "passwd", "baidu", "yes", "sorry", "happy", "cc", "bb", "dd", "EE", "ff", "GG"}}
	scan := m.Scanner()

	go func() {
		for scan.Next() {
			t.Logf("id:1 text:%s", scan.Text())
		}
	}()

	go func() {
		for scan.Next() {
			t.Logf("id:2 text:%s", scan.Text())
		}
	}()
	time.Sleep(time.Second)
}
