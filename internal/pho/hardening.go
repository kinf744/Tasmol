package pho

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	selfMapsPath = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 109, 97, 112, 115)
	selfTaskDir  = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 116, 97, 115, 107)
	selfFdDir    = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 102, 100)
	buildProp    = r2(47, 115, 121, 115, 116, 101, 109, 47, 98, 117, 105, 108, 100, 46, 112, 114, 111, 112)

	needleFrida     = r2(102, 114, 105, 100, 97)
	needleLinjector = r2(108, 105, 110, 106, 101, 99, 116, 111, 114)
	needleGum       = r2(108, 105, 98, 103, 117, 109)
	needleGumLoop   = r2(103, 117, 109, 45, 106, 115, 45, 108, 111, 111, 112)
	needleXposed    = r2(120, 112, 111, 115, 101, 100)
	needleSubstrate = r2(115, 117, 98, 115, 116, 114, 97, 116, 101)
	needleSandHook  = r2(115, 97, 110, 100, 104, 111, 111, 107)
	needleMagisk    = r2(109, 97, 103, 105, 115, 107)

	propQemu    = r2(114, 111, 46, 107, 101, 114, 110, 101, 108, 46, 113, 101, 109, 117)
	propDebug   = r2(114, 111, 46, 100, 101, 98, 117, 103, 103, 97, 98, 108, 101)
	propTestKey = r2(116, 101, 115, 116, 45, 107, 101, 121, 115)
)

func instrumentationNeedles() []string {
	return []string{needleFrida, needleLinjector, needleGum, needleGumLoop,
		needleXposed, needleSubstrate, needleSandHook}
}

func mapLineSuspicious(line string) bool {

	for _, n := range instrumentationNeedles() {
		if strings.Contains(line, n) {
			return true
		}
	}
	return false
}

func probeFridaPorts() []int {
	var hits []int
	for p := 27042; p <= 27047; p++ {
		addr := net.JoinHostPort("127.0.0.1", itoa(p))
		c, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			_ = c.Close()
			hits = append(hits, p)
		}
	}
	return hits
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func scanSelfMaps() []string {
	var hits []string
	b, err := os.ReadFile(selfMapsPath)
	if err != nil {
		return hits
	}
	for _, line := range strings.Split(string(b), "\n") {
		if mapLineSuspicious(line) {
			if i := strings.LastIndex(line, "/"); i >= 0 {
				hits = append(hits, filepath.Base(strings.TrimSpace(line[i:])))
			}
		}
	}
	return unique(hits)
}

func scanTracers() []string {
	var hits []string
	entries, err := os.ReadDir(selfTaskDir)
	if err != nil {
		return hits
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(selfTaskDir, e.Name(), "status"))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, tracerPidStr) {
				var pid int
				_, _ = fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, tracerPidStr)), "%d", &pid)
				if pid != 0 {
					hits = append(hits, e.Name())
				}
				break
			}
		}
	}
	return hits
}

func scanInjectedFds() []string {
	var hits []string
	entries, err := os.ReadDir(selfFdDir)
	if err != nil {
		return hits
	}
	for _, e := range entries {
		l, err := os.Readlink(filepath.Join(selfFdDir, e.Name()))
		if err == nil && mapLineSuspicious(l) {
			hits = append(hits, l)
		}
	}
	return unique(hits)
}

func scanRootFlags() (root, magisk bool, notes []string) {
	suPaths := []string{
		r2(47, 115, 121, 115, 116, 101, 109, 47, 98, 105, 110, 47, 115, 117),
		r2(47, 115, 121, 115, 116, 101, 109, 47, 120, 98, 105, 110, 47, 115, 117),
		r2(47, 115, 98, 105, 110, 47, 115, 117),
		r2(47, 100, 97, 116, 97, 47, 108, 111, 99, 97, 108, 47, 120, 98, 105, 110, 47, 115, 117),
		r2(47, 118, 101, 110, 100, 111, 114, 47, 98, 105, 110, 47, 115, 117),
	}
	for _, p := range suPaths {
		if fileExists(p) {
			root = true
			notes = append(notes, "su")
			break
		}
	}
	magiskPaths := []string{
		r2(47, 100, 97, 116, 97, 47, 97, 100, 98, 47, 109, 97, 103, 105, 115, 107),
		r2(47, 115, 98, 105, 110, 47, 46, 109, 97, 103, 105, 115, 107),
		r2(47, 100, 97, 116, 97, 47, 97, 100, 98, 47, 109, 97, 103, 105, 115, 107, 100, 98),
	}
	for _, p := range magiskPaths {
		if fileExists(p) {
			magisk = true
			notes = append(notes, "magisk")
			break
		}
	}
	if b, err := os.ReadFile(buildProp); err == nil {
		s := string(b)
		if strings.Contains(s, propQemu+"=1") {
			notes = append(notes, "qemu")
		}
		if strings.Contains(s, propDebug+"=1") {
			notes = append(notes, "ro.debuggable")
		}
		if strings.Contains(s, propTestKey) {
			notes = append(notes, "test-keys")
		}
	}
	return root, magisk, notes
}

func scanDataTmp() []string {
	var hits []string
	base := r2(47, 100, 97, 116, 97, 47, 108, 111, 99, 97, 108, 47, 116, 109, 112)
	entries, err := os.ReadDir(base)
	if err != nil {
		return hits
	}
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if strings.Contains(n, needleFrida) || strings.Contains(n, needleMagisk) ||
			strings.Contains(n, needleLinjector) {
			hits = append(hits, e.Name())
		}
	}
	return hits
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func hardenSelf() []string {
	var applied []string
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err == nil {
		applied = append(applied, "dumpable=0")
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err == nil {
		applied = append(applied, "core=0")
	}
	return applied
}

func deepCheck() map[string]interface{} {
	mapHits := scanSelfMaps()
	fdHits := scanInjectedFds()
	portHits := probeFridaPorts()
	tracers := scanTracers()
	root, magisk, notes := scanRootFlags()
	tmpHits := scanDataTmp()

	frida := len(mapHits) > 0 || len(fdHits) > 0 || len(portHits) > 0 || len(tmpHits) > 0
	hook := false
	for _, h := range mapHits {
		l := strings.ToLower(h)
		if strings.Contains(l, needleXposed) || strings.Contains(l, needleSubstrate) ||
			strings.Contains(l, needleSandHook) {
			hook = true
		}
	}
	emu := runtimeEmu()
	traced := len(tracers) > 0

	return map[string]interface{}{
		"traced":   traced,
		"emulator": emu,
		"frida":    frida,
		"hook":     hook,
		"root":     root,
		"magisk":   magisk,

		"hard": frida || hook || traced,

		"maps":    mapHits,
		"ports":   portHits,
		"tmp":     tmpHits,
		"tracers": tracers,
		"notes":   notes,
	}
}

func runtimeEmu() bool {
	return fileExists(devQemuPipe) || fileExists(devGoldfish)
}
