package version

import "testing"

func TestLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.1.0", "0.2.0", true},
		{"0.2.0", "0.2.0", false},
		{"0.2.0", "0.1.0", false},
		{"0.2.0", "0.2.1", true},
		{"0.2.1", "0.2.0", false},
		{"1.0.0", "0.9.9", false},
		{"0.9.9", "1.0.0", true},
		{"0.2", "0.2.0", false},   // missing component counts as 0
		{"0.2.0", "0.2", false},   // symmetric
		{"0.2.0-dev", "0.2.0", false}, // pre-release suffix ignored
		{"0.1.0", "0.2.0-dev", true},
		{"v0.1.0", "v0.2.0", true}, // tolerates a leading v
		{"0.0.0-dev", "0.2.0", true},
		{"", "0.1.0", true},     // empty is oldest
		{"garbage", "0.1.0", true}, // unparseable components count as 0
	}
	for _, c := range cases {
		if got := Less(c.a, c.b); got != c.want {
			t.Errorf("Less(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
