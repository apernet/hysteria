package l2tp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRealmRouterExactMatch(t *testing.T) {
	rr := NewRealmRouter([]RealmRule{
		{Pattern: "ispA.com", Group: "groupA"},
		{Pattern: "ispB.net", Group: "groupB"},
	})
	assert.Equal(t, "groupA", rr.Match("ispA.com"))
	assert.Equal(t, "groupB", rr.Match("ispB.net"))
	assert.Equal(t, "", rr.Match("unknown.com"))
}

func TestRealmRouterWildcard(t *testing.T) {
	rr := NewRealmRouter([]RealmRule{
		{Pattern: "*.example.net", Group: "groupA"},
		{Pattern: "exact.com", Group: "groupB"},
	})
	assert.Equal(t, "groupA", rr.Match("foo.example.net"))
	assert.Equal(t, "groupA", rr.Match("bar.example.net"))
	assert.Equal(t, "", rr.Match("example.net")) // *.x.y does not match x.y
	assert.Equal(t, "groupB", rr.Match("exact.com"))
	assert.Equal(t, "", rr.Match("sub.exact.com"))
}

func TestRealmRouterFirstMatchWins(t *testing.T) {
	rr := NewRealmRouter([]RealmRule{
		{Pattern: "*.example.net", Group: "wildcard"},
		{Pattern: "foo.example.net", Group: "exact"},
	})
	// Wildcard matches first
	assert.Equal(t, "wildcard", rr.Match("foo.example.net"))
}

func TestLoadBalancerRoundRobin(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 1},
			{Address: "lns2:1701", Weight: 1},
		},
	})

	// Should alternate between lns1 and lns2
	results := make(map[string]int)
	for i := 0; i < 10; i++ {
		cfg, ok := lb.PickSticky("group1", "", nil)
		assert.True(t, ok)
		results[cfg.Address]++
	}
	assert.Equal(t, 5, results["lns1:1701"])
	assert.Equal(t, 5, results["lns2:1701"])
}

func TestLoadBalancerWeightedRoundRobin(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 2},
			{Address: "lns2:1701", Weight: 1},
		},
	})

	// With weight 2:1, should get lns1 twice for every lns2
	results := make(map[string]int)
	for i := 0; i < 9; i++ {
		cfg, ok := lb.PickSticky("group1", "", nil)
		assert.True(t, ok)
		results[cfg.Address]++
	}
	assert.Equal(t, 6, results["lns1:1701"])
	assert.Equal(t, 3, results["lns2:1701"])
}

func TestLoadBalancerUnknownGroup(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {{Address: "lns1:1701", Weight: 1}},
	})
	_, ok := lb.PickSticky("nonexistent", "", nil)
	assert.False(t, ok)
}

func TestLoadBalancerDefaultWeight(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 0},  // should default to 1
			{Address: "lns2:1701", Weight: -1}, // should default to 1
		},
	})

	results := make(map[string]int)
	for i := 0; i < 10; i++ {
		cfg, ok := lb.PickSticky("group1", "", nil)
		assert.True(t, ok)
		results[cfg.Address]++
	}
	assert.Equal(t, 5, results["lns1:1701"])
	assert.Equal(t, 5, results["lns2:1701"])
}

func TestPickStickyNoED(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 1},
			{Address: "lns2:1701", Weight: 1},
		},
	})

	// nil ED should fall back to round-robin
	results := make(map[string]int)
	for i := 0; i < 10; i++ {
		cfg, ok := lb.PickSticky("group1", "user@example.com", nil)
		assert.True(t, ok)
		results[cfg.Address]++
	}
	assert.Equal(t, 5, results["lns1:1701"])
	assert.Equal(t, 5, results["lns2:1701"])

	// Empty ED should also fall back to round-robin
	lb2 := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 1},
			{Address: "lns2:1701", Weight: 1},
		},
	})
	results2 := make(map[string]int)
	for i := 0; i < 10; i++ {
		cfg, ok := lb2.PickSticky("group1", "user@example.com", []byte{})
		assert.True(t, ok)
		results2[cfg.Address]++
	}
	assert.Equal(t, 5, results2["lns1:1701"])
	assert.Equal(t, 5, results2["lns2:1701"])
}

func TestPickStickyWithED(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 1},
			{Address: "lns2:1701", Weight: 1},
		},
	})

	ed := []byte{0x01, 0x0A, 0x0B, 0x0C, 0x0D} // class=1 (locally assigned), address

	// Same (username, ed) should always return the same LNS
	first, ok := lb.PickSticky("group1", "user@example.com", ed)
	assert.True(t, ok)
	for i := 0; i < 100; i++ {
		cfg, ok := lb.PickSticky("group1", "user@example.com", ed)
		assert.True(t, ok)
		assert.Equal(t, first.Address, cfg.Address)
	}
}

func TestPickStickyDifferentED(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 1},
			{Address: "lns2:1701", Weight: 1},
		},
	})

	ed1 := []byte{0x01, 0x0A, 0x0B, 0x0C, 0x0D}
	ed2 := []byte{0x01, 0xFF, 0xFE, 0xFD, 0xFC}

	cfg1, _ := lb.PickSticky("group1", "user@example.com", ed1)
	cfg2, _ := lb.PickSticky("group1", "user@example.com", ed2)

	// Different EDs may (but aren't guaranteed to) map to different LNSes.
	// With only 2 LNSes and a good hash, these particular inputs do differ.
	// The critical invariant is that each is individually stable:
	for i := 0; i < 50; i++ {
		c1, _ := lb.PickSticky("group1", "user@example.com", ed1)
		c2, _ := lb.PickSticky("group1", "user@example.com", ed2)
		assert.Equal(t, cfg1.Address, c1.Address)
		assert.Equal(t, cfg2.Address, c2.Address)
	}
}

func TestPickStickyWeighted(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {
			{Address: "lns1:1701", Weight: 2},
			{Address: "lns2:1701", Weight: 1},
		},
	})

	// With weight 2:1 (flatList = [lns1, lns1, lns2]), distribution over many
	// random (username, ed) pairs should approximate 2:1.
	results := make(map[string]int)
	for i := 0; i < 3000; i++ {
		ed := []byte{byte(i >> 8), byte(i)}
		cfg, ok := lb.PickSticky("group1", "user@example.com", ed)
		assert.True(t, ok)
		results[cfg.Address]++
	}
	// Expect ~2000 for lns1 and ~1000 for lns2. Allow wide margin for hash distribution.
	assert.Greater(t, results["lns1:1701"], 1500, "lns1 should get roughly 2/3 of picks")
	assert.Greater(t, results["lns2:1701"], 500, "lns2 should get roughly 1/3 of picks")
}

func TestPickStickyUnknownGroup(t *testing.T) {
	lb := NewLoadBalancer(map[string][]LNSConfig{
		"group1": {{Address: "lns1:1701", Weight: 1}},
	})
	_, ok := lb.PickSticky("nonexistent", "user", []byte{0x01})
	assert.False(t, ok)
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		realm   string
		want    bool
	}{
		{"ispA.com", "ispA.com", true},
		{"ispA.com", "ispB.com", false},
		{"*.example.net", "foo.example.net", true},
		{"*.example.net", "bar.example.net", true},
		{"*.example.net", "example.net", false},
		{"*.example.net", "deep.sub.example.net", true},
		{"*", "anything", false}, // single * without dot is not a valid wildcard
		{"", "", true},           // empty matches empty
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, matchPattern(tt.pattern, tt.realm),
			"matchPattern(%q, %q)", tt.pattern, tt.realm)
	}
}
