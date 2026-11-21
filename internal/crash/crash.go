package crash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// CrashReporter handles crash reporting to the stivaros API
type CrashReporter struct {
	apiURL     string
	appVersion string
	uuid       string
	platform   string
	client     *http.Client
}

// CrashReport represents a crash report to be sent to the API
type CrashReport struct {
	UUID          string `json:"uuid"`
	Platform      string `json:"platform"`       // "go" or "android"
	AppVersion    string `json:"app_version"`
	AndroidVersion string `json:"android_version"`
	DeviceModel   string `json:"device_model"`
	CrashType     string `json:"crash_type"`      // "crash", "panic", "disconnect", "error", "exception"
	CrashMessage  string `json:"crash_message"`
	StackTrace    string `json:"stack_trace"`
	ThreadName    string `json:"thread_name"`
	Timestamp     int64  `json:"timestamp"`
}

var (
	globalReporter *CrashReporter
	globalMu       sync.Mutex
)

// NewCrashReporter creates a new crash reporter
func NewCrashReporter(apiURL, uuid, appVersion string) *CrashReporter {
	return &CrashReporter{
		apiURL:     strings.TrimRight(apiURL, "/"),
		appVersion: appVersion,
		uuid:       uuid,
		platform:   "go",
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// InitCrashReporter initializes the global crash reporter and installs a
// process-wide panic handler that reports panics to the API.
func InitCrashReporter(apiURL, uuid, appVersion string) *CrashReporter {
	reporter := NewCrashReporter(apiURL, uuid, appVersion)
	globalMu.Lock()
	globalReporter = reporter
	globalMu.Unlock()

	// Install a panic handler on the main goroutine so that any unrecovered
	// panic in main is reported before the process exits.
	go installMainPanicHandler(reporter)

	return reporter
}

// GlobalReporter returns the package-level reporter, or nil if not initialized.
func GlobalReporter() *CrashReporter {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalReporter
}

// ReportPanic recovers from a panic and reports it using the global reporter.
func ReportPanic() {
	if r := recover(); r != nil {
		stack := debug.Stack()
		msg := fmt.Sprintf("Panic: %v", r)
		rep := GlobalReporter()
		if rep != nil {
			rep.reportCrash("panic", msg, string(stack), "main")
		}
		// Re-panic so the crash still propagates
		panic(r)
	}
}

// ReportError reports a generic error using the global reporter.
func ReportError(err error, context string) {
	if err == nil {
		return
	}
	msg := err.Error()
	if context != "" {
		msg = context + ": " + msg
	}
	rep := GlobalReporter()
	if rep != nil {
		rep.reportCrash("error", msg, "", "background")
	}
}

// ReportDisconnect reports a disconnection issue using the global reporter.
func ReportDisconnect(reason string, details string) {
	msg := reason
	if details != "" {
		msg += ": " + details
	}
	rep := GlobalReporter()
	if rep != nil {
		rep.reportCrash("disconnect", msg, "", "tunnel")
	}
}

// ReportException reports an exception with stack trace using the global reporter.
func ReportException(err error, stackTrace string) {
	if err == nil {
		return
	}
	rep := GlobalReporter()
	if rep != nil {
		rep.reportCrash("exception", err.Error(), stackTrace, "tunnel")
	}
}

// CrashHandler wraps a function with panic recovery and reporting.
func CrashHandler(fn func()) {
	defer ReportPanic()
	fn()
}

// CrashHandlerWithContext wraps a function with context for crash reporting.
func CrashHandlerWithContext(context string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			msg := fmt.Sprintf("Panic in %s: %v", context, r)
			rep := GlobalReporter()
			if rep != nil {
				rep.reportCrash("panic", msg, string(stack), "goroutine")
			}
			panic(r)
		}
	}()
	fn()
}

// installMainPanicHandler installs a deferred panic handler on a goroutine
// that runs for the lifetime of the process, catching any panic that escapes
// all other recovery.
func installMainPanicHandler(rep *CrashReporter) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			msg := fmt.Sprintf("Unrecovered panic: %v", r)
			rep.reportCrash("panic", msg, string(stack), "main")
			os.Exit(1)
		}
	}()
	// Keep this goroutine alive forever
	select {}
}

// SetUUID sets the UUID for the crash reporter
func (cr *CrashReporter) SetUUID(uuid string) {
	cr.uuid = uuid
}

// ReportPanic recovers from a panic and reports it
func (cr *CrashReporter) ReportPanic() {
	if r := recover(); r != nil {
		stack := debug.Stack()
		cr.reportCrash("panic", fmt.Sprintf("Panic: %v", r), string(stack), "main")
		panic(r)
	}
}

// ReportError reports a generic error
func (cr *CrashReporter) ReportError(err error, context string) {
	if err != nil {
		msg := err.Error()
		if context != "" {
			msg = context + ": " + msg
		}
		cr.reportCrash("error", msg, "", "background")
	}
}

// ReportDisconnect reports a disconnection issue
func (cr *CrashReporter) ReportDisconnect(reason string, details string) {
	msg := reason
	if details != "" {
		msg += ": " + details
	}
	cr.reportCrash("disconnect", msg, "", "tunnel")
}

// ReportException reports an exception with stack trace
func (cr *CrashReporter) ReportException(err error, stackTrace string) {
	if err != nil {
		cr.reportCrash("exception", err.Error(), stackTrace, "tunnel")
	}
}

// reportCrash sends a crash report to the API
func (cr *CrashReporter) reportCrash(crashType, crashMessage, stackTrace, threadName string) {
	if cr.uuid == "" || cr.apiURL == "" {
		return // Cannot report without UUID or API URL
	}

	report := CrashReport{
		UUID:          cr.uuid,
		Platform:      cr.platform,
		AppVersion:    cr.appVersion,
		DeviceModel:   getDeviceModel(),
		CrashType:     crashType,
		CrashMessage:  crashMessage,
		StackTrace:    stackTrace,
		ThreadName:    threadName,
		Timestamp:     time.Now().Unix(),
	}

	go cr.sendReport(report)
}

// sendReport sends the crash report to the API
func (cr *CrashReporter) sendReport(report CrashReport) {
	data, err := json.Marshal(report)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", cr.apiURL+"/api/v1/crash/report", bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cr.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// getDeviceModel returns the device/model info
func getDeviceModel() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%s/%s", runtime.GOOS, hostname)
}

// LogCrash logs a crash locally (for debugging)
func LogCrash(crashType, message, stackTrace string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(os.Stderr, "[CRASH %s] %s: %s\n%s\n", timestamp, crashType, message, stackTrace)
}

// CaptureStackTrace returns the current stack trace as a string
func CaptureStackTrace() string {
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}