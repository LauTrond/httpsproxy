package httpsproxy

import (
	"testing"
	"time"
	"fmt"
)

func TestSign(t *testing.T) {
	start := time.Now()
	cer, key, err := SignRoot(start.AddDate(1, 0, 0))
	if err != nil { t.Fatal(err) }
	fmt.Println(time.Since(start).Seconds(), "sec")

	start = time.Now()
	_, _, err = SignHost("test.com", cer, key, start.AddDate(0, 1, 0))
	if err != nil { t.Fatal(err) }
	fmt.Println(time.Since(start).Seconds(), "sec")
}
