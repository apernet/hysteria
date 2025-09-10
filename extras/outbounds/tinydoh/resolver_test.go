package tinydoh

import (
	"fmt"
	"testing"
)

func TestResolver(t *testing.T) {
	r := &Resolver{
		URL: "https://1.1.1.1/dns-query",
	}
	ipv4, err := r.LookupA("www.wikipedia.org")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(ipv4)
	ipv6, err := r.LookupAAAA("www.wikipedia.org")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(ipv6)
}
