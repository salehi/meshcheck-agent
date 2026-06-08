// SPDX-License-Identifier: Apache-2.0

// Package version compares MeshCheck agent version strings. The agent versions
// are plain dotted-numeric semver (e.g. "0.2.0"); a build with no injected
// version reports "0.0.0-dev". The vendor tree carries no semver library and
// the comparison this project needs is small, so it lives here and is shared by
// the gateway (deciding whether to offer an update) and the agent (refusing an
// offer that is not actually newer).
package version

import (
	"strconv"
	"strings"
)

// Less reports whether version a is strictly older than version b. Each version
// is split on "." and compared component by component as integers; a missing
// trailing component counts as 0, so "0.2" == "0.2.0". Any pre-release or build
// suffix (after the first "-" or "+") is ignored, so "0.2.0-dev" compares equal
// to "0.2.0". A component that does not parse as an integer counts as 0, which
// keeps a malformed version from ever being treated as newer.
func Less(a, b string) bool {
	pa, pb := parse(a), parse(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// parse splits a version into its numeric components, dropping any pre-release
// or build metadata suffix.
func parse(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		out[i] = n
	}
	return out
}
