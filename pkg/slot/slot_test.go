package slot

import "testing"

func TestOfAndStartAgree(t *testing.T) {
	const iv, ph = 10, 3_250 // every 10 s, 3.25 s into the interval
	for _, tc := range []struct {
		t    int64
		want int64
	}{
		{3_250, 0},          // exactly the start of slot 0
		{13_249, 0},         // the last millisecond of slot 0
		{13_250, 1},         // slot 1 starts
		{0, -1},             // before slot 0's start
		{-6_750, -1},        // exactly slot -1's start
		{-6_751, -2},        // floor division for negative instants
		{1_760_000_003_250, 176_000_000},
	} {
		if got := Of(tc.t, iv, ph); got != tc.want {
			t.Errorf("Of(%d) = %d, want %d", tc.t, got, tc.want)
		}
		k := Of(tc.t, iv, ph)
		if s := Start(k, iv, ph); s > tc.t || tc.t >= Start(k+1, iv, ph) {
			t.Errorf("t=%d not inside slot %d [%d, %d)", tc.t, k, s, Start(k+1, iv, ph))
		}
	}
}

func TestPhaseIsStableAndInRange(t *testing.T) {
	ids := []string{"01M52C3D8QHNWGJKSTEVWFXT5H", "01M51ZKV3SWBNHQ06J4FF1F5A4", "a", ""}
	for _, id := range ids {
		p := Phase(id, 10)
		if p < 0 || p >= 10_000 {
			t.Errorf("Phase(%q) = %d, outside [0, 10000)", id, p)
		}
		if Phase(id, 10) != p {
			t.Errorf("Phase(%q) is not stable", id)
		}
	}
}

func TestPhaseSpreadsMonitors(t *testing.T) {
	// 1,000 Monitors on a 60 s interval should land in most of the 60
	// one-second buckets, not pile onto a few.
	buckets := map[int32]bool{}
	for i := 0; i < 1000; i++ {
		buckets[Phase(string(rune('A'+i%26))+string(rune(i)), 60)/1000] = true
	}
	if len(buckets) < 55 {
		t.Errorf("1000 phases fell in only %d of 60 seconds", len(buckets))
	}
}

func TestMalformedIntervalDoesNotPanic(t *testing.T) {
	_ = Of(12345, 0, 0)
	_ = Phase("x", 0)
}
