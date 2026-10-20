package pho

// Durcissement anti-analyse dynamique (RASP) pour le plan de contrôle.
//
// Menaces couvertes :
//   - Frida / gadget / injection (frida-server, frida-agent, gum, linjector)
//   - Frameworks de hook : Xposed / EdXposed / LSPosed / Substrate / SandHook
//   - Débogueurs : TracerPid sur TOUS les threads (pas seulement le principal)
//   - Émulateurs : qemu_pipe, goldfish, build.prop (ro.kernel.qemu)
//   - Root : binaires su, Magisk (data/adb, .magisk)
//   - Anti-ptrace : PR_SET_DUMPABLE=0 (le processus n'est plus attachable)
//   - Anti-dump mémoire : RLIMIT_CORE=0 (pas de core dump avec les clés)
//
// Les sondes sont exécutées depuis le code natif garblé (et non Java) :
// un hook Java ne voit rien, et les chaînes de détection sont reconstruites
// par code points (jamais contiguës dans le .so).

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// -- Chaînes de détection (jamais en clair dans le binaire) ---------------

var (
	selfMapsPath = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 109, 97, 112, 115)                 // /proc/self/maps
	selfTaskDir  = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 116, 97, 115, 107)                 // /proc/self/task
	selfFdDir    = r2(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 102, 100)                          // /proc/self/fd
	buildProp    = r2(47, 115, 121, 115, 116, 101, 109, 47, 98, 117, 105, 108, 100, 46, 112, 114, 111, 112) // /system/build.prop

	// Aiguilles instrumentation (maps, fd, /data/local/tmp).
	needleFrida     = r2(102, 114, 105, 100, 97)                              // "frida"
	needleLinjector = r2(108, 105, 110, 106, 101, 99, 116, 111, 114)          // "linjector"
	needleGum       = r2(108, 105, 98, 103, 117, 109)                         // "libgum"
	needleGumLoop   = r2(103, 117, 109, 45, 106, 115, 45, 108, 111, 111, 112) // "gum-js-loop"
	needleXposed    = r2(120, 112, 111, 115, 101, 100)                        // "xposed"
	needleSubstrate = r2(115, 117, 98, 115, 116, 114, 97, 116, 101)           // "substrate"
	needleSandHook  = r2(115, 97, 110, 100, 104, 111, 111, 107)               // "sandhook"
	needleMagisk    = r2(109, 97, 103, 105, 115, 107)                         // "magisk"

	// build.prop
	propQemu    = r2(114, 111, 46, 107, 101, 114, 110, 101, 108, 46, 113, 101, 109, 117) // "ro.kernel.qemu"
	propDebug   = r2(114, 111, 46, 100, 101, 98, 117, 103, 103, 97, 98, 108, 101)        // "ro.debuggable"
	propTestKey = r2(116, 101, 115, 116, 45, 107, 101, 121, 115)                         // "test-keys"
)

// instrumentationNeedles : aiguilles frida / hook recherchées dans
// /proc/self/maps et /proc/self/fd.
func instrumentationNeedles() []string {
	return []string{needleFrida, needleLinjector, needleGum, needleGumLoop,
		needleXposed, needleSubstrate, needleSandHook}
}

// mapLineSuspicious retourne vrai si une ligne de maps/fd matche une aiguille.
func mapLineSuspicious(line string) bool {
	// Minuscules seulement : les chemins frida/hook le sont déjà, et on
	// évite un ToLower() sur la ligne entière pour ne pas payer une
	// allocation par ligne.
	for _, n := range instrumentationNeedles() {
		if strings.Contains(line, n) {
			return true
		}
	}
	return false
}

// probeFridaPorts teste les ports d'écoute par défaut de frida-server /
// gadget (27042-27047) sur loopback. Une connexion acceptée = agent présent.
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

// scanSelfMaps détecte les bibliothèques injectées dans NOTRE espace
// mémoire (frida-agent, gadget, xposed bridges locaux).
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

// scanTracers vérifie TracerPid pour CHAQUE thread (/proc/self/task/*/status) :
// un attachement ptrace sur un thread secondaire passe inaperçu du seul
// status principal.
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

// scanInjectedFds repère les pipes/fichiers d'injection ouverts par le
// processus (linjector de frida).
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

// scanRootFlags : binaires su / Magisk / build.prop. Lecture non-root des
// chemins protégés échoue silencieusement — un faux négatif n'est pas grave,
// le flag root est informatif (soft), pas bloquant.
func scanRootFlags() (root, magisk bool, notes []string) {
	suPaths := []string{
		r2(47, 115, 121, 115, 116, 101, 109, 47, 98, 105, 110, 47, 115, 117),                     // /system/bin/su
		r2(47, 115, 121, 115, 116, 101, 109, 47, 120, 98, 105, 110, 47, 115, 117),                // /system/xbin/su
		r2(47, 115, 98, 105, 110, 47, 115, 117),                                                  // /sbin/su
		r2(47, 100, 97, 116, 97, 47, 108, 111, 99, 97, 108, 47, 120, 98, 105, 110, 47, 115, 117), // /data/local/xbin/su
		r2(47, 118, 101, 110, 100, 111, 114, 47, 98, 105, 110, 47, 115, 117),                     // /vendor/bin/su
	}
	for _, p := range suPaths {
		if fileExists(p) {
			root = true
			notes = append(notes, "su")
			break
		}
	}
	magiskPaths := []string{
		r2(47, 100, 97, 116, 97, 47, 97, 100, 98, 47, 109, 97, 103, 105, 115, 107),          // /data/adb/magisk
		r2(47, 115, 98, 105, 110, 47, 46, 109, 97, 103, 105, 115, 107),                      // /sbin/.magisk
		r2(47, 100, 97, 116, 97, 47, 97, 100, 98, 47, 109, 97, 103, 105, 115, 107, 100, 98), // /data/adb/magiskdb
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

// scanDataTmpTmp frida / gadget en attente dans /data/local/tmp (visible
// même sans root pour les noms classiques).
func scanDataTmp() []string {
	var hits []string
	base := r2(47, 100, 97, 116, 97, 47, 108, 111, 99, 97, 108, 47, 116, 109, 112) // /data/local/tmp
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

// hardenSelf applique les protections passives du processus (une fois) :
//   - PR_SET_DUMPABLE=0 : plus attachable par ptrace (gdb, simple attach)
//   - RLIMIT_CORE=0 : aucun core dump (les clés ne finissent pas sur disque)
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

// deepCheck exécute toutes les sondes actives et retourne un verdict JSON.
// Coût : ~ms (lectures /proc + 6 connexions loopback 150 ms max).
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
		// Verdict bloquant : instrumentation ou débogage actif.
		"hard": frida || hook || traced,
		// Détails (usage diagnostic, non sensibles).
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
