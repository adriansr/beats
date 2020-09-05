// +build amd64,linux

package cmd

import (
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/elastic/beats/v7/auditbeat/cmd"
	"github.com/elastic/beats/v7/auditbeat/module/auditd"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/service"
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

type sorter struct {
	name   string
	value  func(*auditd.Counter) float64
	format func(float64) string
}

var (
	auditdOverheadCmd = &cobra.Command{
		Use:  "auditd-overhead",
		Long: "Show audit overhead on syscalls",
		Run: func(cmd *cobra.Command, args []string) {
			if err := runAuditOverhead(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
		},
	}

	syscallNames = auparse.AuditSyscalls["x86_64"]

	log *logp.Logger

	sortTypes = []sorter{
		{
			name: "Per-call overhead time",
			format: func(v float64) string {
				return format(uint64(v))
			},
			value: func(counter *auditd.Counter) float64 {
				return float64(counter.TimeIn) / float64(counter.NumCalls)
			},
		},
		{
			name: "Total overhead time",
			format: func(v float64) string {
				return format(uint64(v))
			},
			value: func(counter *auditd.Counter) float64 {
				return float64(counter.TimeIn)
			},
		},
	}

	selectedSort = 0

	spaces = "                                                                                          "
)

func init() {
	auditdOverheadCmd.Flags().AddGoFlag(flag.CommandLine.Lookup("httpprof"))
	auditdOverheadCmd.Flags().BoolP("interactive", "i", false, "interactive mode")
	auditdOverheadCmd.Flags().DurationP("time", "t", 30*time.Second, "monitoring time")
	cmd.ShowCmd.AddCommand(auditdOverheadCmd)
}

var durationUnits = []struct {
	unit  string
	value time.Duration
}{
	{unit: "ns", value: time.Nanosecond},
	{unit: "µs", value: time.Microsecond},
	{unit: "ms", value: time.Millisecond},
	{unit: "s", value: time.Second},
	{unit: "m", value: time.Minute},
	{unit: "h", value: time.Hour},
	{unit: "d", value: time.Hour * 24},
	{unit: "?", value: math.MaxInt64},
}

func format(duration uint64) string {
	for idx, u := range durationUnits[:len(durationUnits)-1] {
		if duration < uint64(durationUnits[idx+1].value.Nanoseconds()) {
			return fmt.Sprintf("%.1f%s", float64(duration)/float64(u.value), u.unit)
		}
	}
	return time.Duration(duration).String()
}

func runAuditOverhead(cmd *cobra.Command, args []string) (err error) {
	// This enables the httpprof server.
	service.BeforeRun()

	// Connect to auditd client
	auditCli, err := libaudit.NewAuditClient(nil)
	if err != nil {
		return errors.Wrap(err, "connecting to audit")
	}
	defer func() {
		if err := auditCli.Close(); err != nil {
			log.Errorf("Failed stopping audit client")
		}
	}()

	// Launch syscall monitor
	monitor := auditd.SyscallMonitor.Get()
	if monitor == nil {
		return errors.New("syscall monitor is not available")
	}
	if err = monitor.Start(); err != nil {
		return errors.Wrap(err, "failed to start syscall monitor")
	}
	defer func() {
		if err := monitor.Stop(); err != nil {
			log.Errorf("Failed stopping syscall monitor: %v", err)
		}
	}()

	if interactive, _ := cmd.Flags().GetBool("interactive"); interactive {
		return runInteractive(monitor, auditCli)
	}

	duration, _ := cmd.Flags().GetDuration("time")
	deadlineC := time.After(duration)

	fmt.Fprintf(os.Stderr, "Monitoring syscall overhead for %v ...\n", duration)

	initialStatus, err := GetAuditStatus(auditCli, true, false /*TODO*/)
	if err != nil {
		return err
	}
	<-deadlineC

	stats := monitor.Stats()
	finalStatus, err := GetAuditStatus(auditCli, true, false /*TODO*/)
	if err != nil {
		return err
	}

	fmt.Printf("Auditbeat syscall overhead report\n")
	fmt.Printf("=================================\n")
	fmt.Printf("Date: %s\n", time.Now().Format(time.RFC3339))
	fmt.Printf("Duration: %s\n", duration)
	fmt.Printf("Auditd status (at start):\n")
	initialStatus.Print()
	fmt.Println()
	fmt.Printf("Auditd status (at end):\n")
	finalStatus.Print()
	fmt.Println()
	fmt.Printf("Number of syscall functions monitored: %d\n", len(stats.Counters))
	fmt.Printf("Total calls: %d\n", stats.Calls)
	fmt.Printf("Tracing events lost: %d\n", stats.Lost)

	counters := make([]*auditd.Counter, 0, len(stats.Counters))
	for _, v := range stats.Counters {
		counters = append(counters, v)
	}
	sort.Slice(counters, func(i, j int) bool {
		return syscallNames[int(counters[i].SysNo)] < syscallNames[int(counters[j].SysNo)]
	})
	for _, ct := range counters {
		fmt.Printf("- %s sysno:%d calls:%d audit_time:%s\n", syscallNames[int(ct.SysNo)], ct.SysNo, ct.NumCalls, format(ct.TimeIn))
	}
	fmt.Println()
	for _, st := range sortTypes {
		sort.Slice(counters, func(i, j int) bool {
			return st.value(counters[i]) > st.value(counters[j])
		})
		fmt.Printf("Sorted by: %s\n", st.name)
		for _, ct := range counters {
			fmt.Printf("- %s %s\n", syscallNames[int(ct.SysNo)], st.format(st.value(ct)))
		}
		fmt.Println()
	}
	return nil
}

type auditStatus struct {
	rules        []string
	auditProgram string
	status       libaudit.AuditStatus
}

func GetAuditStatus(auditCli *libaudit.AuditClient, fetchRules, resolveIDs bool) (st auditStatus, err error) {
	status, err := auditCli.GetStatus()
	if err != nil {
		return st, errors.Wrap(err, "getting audit rules")
	}

	if fetchRules {
		rawRules, err := auditCli.GetRules()
		if err != nil {
			return st, errors.Wrap(err, "getting audit rules")
		}
		st.rules = make([]string, len(rawRules))
		for idx, raw := range rawRules {
			if st.rules[idx], err = rule.ToCommandLine(raw, resolveIDs); err != nil {
				return st, errors.Wrapf(err, "parsing rule %d", idx+1)
			}
		}
	}
	st.status = *status
	if st.status.PID != 0 {
		st.auditProgram = getProgramNameFromPID(st.status.PID)
	}
	return st, nil
}

func (st auditStatus) Print() {
	fmt.Printf("- pid: %d\n", st.status.PID)
	if st.auditProgram != "" {
		fmt.Printf("- program: %s\n", st.auditProgram)
	}
	fmt.Printf("- enabled: %d\n", st.status.Enabled)
	fmt.Printf("- failure: %d\n", st.status.Failure)
	fmt.Printf("- lost: %d\n", st.status.Lost)
	fmt.Printf("- backlog: %d\n", st.status.Backlog)
	fmt.Printf("- backlog_limit: %d\n", st.status.BacklogLimit)
	fmt.Printf("- backlog_wait_time: %d\n", st.status.BacklogWaitTime)
	fmt.Printf("- rate_limit: %d\n", st.status.RateLimit)
	fmt.Printf("- feature_bitmap: %#x\n", st.status.FeatureBitmap)
	fmt.Printf("- rules: %d\n", len(st.rules))
	for idx, rule := range st.rules {
		fmt.Printf(" %d: %s\n", idx+1, rule)
	}
}
func runInteractive(monitor auditd.Monitor, auditCli *libaudit.AuditClient) (err error) {
	log = logp.NewLogger("audit_overhead")
	if !terminal.IsTerminal(0) {
		return errors.New("must be run from an ANSI terminal")
	}
	prevState, err := terminal.MakeRaw(0)
	if err != nil {
		return errors.Wrap(err, "unable to set terminal in raw mode")
	}
	defer func() {
		if err := terminal.Restore(0, prevState); err != nil {
			log.Errorf("Failed to restore terminal. Try running `reset` to fix. error=%v", err)
		}
	}()

	inputC := make(chan byte, 0)
	go func() {
		var chr [1]byte
		for {
			n, err := os.Stdin.Read(chr[:])
			if err != nil || n == 0 {
				log.Errorf("Error reading input from terminal: %v")
				inputC <- 'q'
				return
			}
			inputC <- chr[0]
		}
	}()

	// Enter "alternate screen"
	fmt.Print("\033[?1049h")
	// Leave alternate screen on termination
	defer fmt.Print("\033[?1049l")

	timerC := time.Tick(2 * time.Second)
	paused := false
	forceUpdate := false

	auditStatus, err := auditCli.GetStatus()
	if err != nil {
		return errors.Wrap(err, "failed getting audit state")
	}

	stats := monitor.Stats()
	// Wait until some stats
	for it := 0; it < 10 && len(stats.Counters) == 0; it++ {
		time.Sleep(time.Second / 10)
	}

	for {
		if !paused || forceUpdate {
			if err := display(stats, auditStatus); err != nil {
				panic(err)
			}
			forceUpdate = false
		}
		if paused {
			w, h, err := terminal.GetSize(0)
			if err != nil {
				panic(err)
			}
			const paused = "[PAUSED]"
			var t termBuffer
			t.MoveTo(h, w-len(paused))
			t.SetColor(Yellow).SetColor(Red.bg().bright())
			t.Print(paused).SetColor(Default).Write()
		}

		select {
		case chr := <-inputC:
			switch chr {
			case 0, 'q', 'Q':
				fmt.Printf("Exit\r\n")
				return nil
			case 's':
				selectedSort = (selectedSort + 1) % len(sortTypes)
				forceUpdate = true
			case 'S':
				selectedSort -= 1
				if selectedSort < 0 {
					selectedSort = len(sortTypes) - 1
				}
				forceUpdate = true
			case 'p', 'P':
				paused = !paused
			case 'r', 'R':
				monitor.Clear()
			}

		case <-timerC:
			stats = monitor.Stats()
			if auditStatus, err = auditCli.GetStatus(); err != nil {
				return errors.Wrap(err, "failed getting audit state")
			}
		}
	}
}

type termBuffer struct {
	data []byte
}

func (t *termBuffer) Print(msg string) *termBuffer {
	t.data = append(t.data, []byte(msg)...)
	return t
}

func (t *termBuffer) Printf(format string, args ...interface{}) *termBuffer {
	return t.Print(fmt.Sprintf(format, args...))
}

func (t *termBuffer) ClearBelowCursor() *termBuffer {
	return t.Print("\033[J")
}

func (t *termBuffer) MoveTo(row, col int) *termBuffer {
	return t.Printf("\033[%d;%dH", row, col)
}

type Color byte

const (
	Default Color = 0
	Black   Color = iota + 29
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

func (c Color) bg() Color {
	if c != Default {
		c += 10
	}
	return c
}

func (c Color) bright() Color {
	return c | 0x80
}

func (c Color) underline() Color {
	return c | 0x40
}

func (t *termBuffer) SetColor(c Color) *termBuffer {
	extra := ""
	if c&0x80 != 0 {
		extra = ";1"
	}
	if c&0x40 != 0 {
		extra += ";4"
	}
	c &= 0x3f
	return t.Printf("\033[%d%sm", c, extra)
}

func (t *termBuffer) Fill(n int) *termBuffer {
	for ; n > len(spaces); n -= len(spaces) {
		t.Print(spaces)
	}
	if n > 0 {
		t.Print(spaces[:n])
	}
	return t
}

func (t *termBuffer) CRLF() *termBuffer {
	return t.Print("\r\n")
}

func (t *termBuffer) Write() *termBuffer {
	fmt.Print(string(t.data))
	t.data = t.data[:0]
	return t
}

var columns = []string{
	" SYSCALL",
	" NUM CALLS",
	" KERN TIME",
	" AUDIT TIME",
	" VALUE",
}

var keys = [][2]string{
	{"[q]", "Exit "},
	{"[s]", "Next sort "},
	{"[S]", "Prev sort "},
	{"[P]", "Pause "},
	{"[R]", "Reset stats "},
}

var widths []int

func display(stats auditd.Stats, auditStatus *libaudit.AuditStatus) error {
	width, height, err := terminal.GetSize(0)
	if err != nil {
		return err
	}
	sorter := sortTypes[selectedSort]
	counters := make([]*auditd.Counter, 0, len(stats.Counters))
	for _, v := range stats.Counters {
		counters = append(counters, v)
	}
	sort.Slice(counters, func(i, j int) bool {
		return sorter.value(counters[i]) > sorter.value(counters[j])
	})
	limit, excess := len(counters), 0
	const fixedLines = 6
	if limit > height-fixedLines {
		limit = height - fixedLines
		excess = len(counters) - limit
	}
	var table = make([][]string, limit)
	if widths == nil {
		widths = make([]int, len(columns))
		for idx, col := range columns {
			widths[idx] = len(col)
		}
	}
	var maxVal float64
	for idx, ct := range counters[:limit] {
		name := syscallNames[int(ct.SysNo)]
		if name == "" {
			name = fmt.Sprintf("???(%d)", ct.SysNo)
		}
		value := sorter.value(ct)
		if value > maxVal {
			maxVal = value
		}
		table[idx] = []string{
			name,
			fmt.Sprintf(" %d", ct.NumCalls),
			"-",
			fmt.Sprintf(" %s", format(ct.TimeIn)),
			fmt.Sprintf(" %s", sorter.format(value)),
		}
		for j, str := range table[idx] {
			if n := utf8.RuneCountInString(str); n > widths[j] {
				widths[j] = n
			}
		}
	}

	var t termBuffer
	// Clear the screen and move cursor to the top-left
	t.MoveTo(0, 0).ClearBelowCursor()
	// Audit status line
	t.SetColor(Green.bright()).Print("AUDIT STATUS").SetColor(Default)
	t.SetColor(Default).SetColor(Cyan).Print(" PID: ")
	if auditStatus.PID != 0 {
		t.SetColor(Default).SetColor(Cyan).Printf("[%d]", auditStatus.PID)
		t.SetColor(Cyan.bright()).Printf(" %s", getProgramNameFromPID(auditStatus.PID))
	} else {
		t.SetColor(Cyan).Print("(none)")
	}
	t.CRLF()
	t.SetColor(Default).SetColor(Cyan.underline()).Print("             Backlog: ")
	t.SetColor(Cyan.bright().underline()).Printf("%5d", auditStatus.Backlog)
	t.SetColor(Default).SetColor(Cyan.underline()).Printf("/%-5d", auditStatus.BacklogLimit)
	t.SetColor(Default).SetColor(Cyan.underline()).Print(" Lost: ")
	t.SetColor(Red.bright().underline()).Printf("%-10d", auditStatus.Lost).SetColor(Default)
	t.SetColor(Default).SetColor(Cyan.underline()).Print(" Failures: ")
	t.SetColor(Yellow.bright().underline()).Printf("%-10d", auditStatus.Failure)
	// This needs to be adjusted to the size of this line
	t.SetColor(Cyan.bright().underline()).Fill(width - 71).SetColor(Default).CRLF()

	t.SetColor(Green.bright()).Print("MONITORING  ").SetColor(Default)
	t.SetColor(Default).SetColor(Cyan).Print(" Syscalls: ")
	t.SetColor(Cyan.bright()).Printf("%4d", len(counters))
	t.SetColor(Default).SetColor(Cyan).Print("     Events: ")
	t.SetColor(Cyan.bright()).Printf("%-10d", stats.Calls)
	t.SetColor(Default).SetColor(Cyan).Print("  Dropped: ")
	t.SetColor(Red.bright()).Printf("%-10d", stats.Lost)
	t.CRLF()

	// Sort line
	const sortBy = " Sorted by: "
	t.SetColor(Default).SetColor(White.bg()).SetColor(Black).Print(sortBy)
	t.SetColor(Yellow).SetColor(Cyan.bright().bg()).Print(sorter.name)
	t.Fill(width - len(sorter.name) - len(sortBy)).CRLF()

	// Table header
	t.SetColor(Default).SetColor(White).SetColor(Blue.bright().bg())
	remain := width
	for idx, w := range widths {
		t.Fill(w - len(columns[idx])).Print(columns[idx])
		remain -= w
	}
	t.Fill(remain).CRLF()
	graphSize := remain - 1
	const maxGraphSize = 50
	if graphSize > maxGraphSize {
		graphSize = maxGraphSize
	}
	t.SetColor(Default)
	for idx, row := range table {
		for col, w := range widths {
			t.Fill(w - utf8.RuneCountInString(row[col])).Print(row[col])
		}
		t.Print(" ")
		if idx&1 != 0 {
			t.SetColor(Green.bg())
		} else {
			t.SetColor(Green.bg())
		}
		t.Fill(int(float64(graphSize) * sorter.value(counters[idx]) / maxVal))
		t.SetColor(Default).CRLF()
	}
	if excess > 0 {
		//fmt.Printf("[... and %d more ...]\r\n", excess)
	}
	t.MoveTo(height, 0)
	remain = width
	for _, k := range keys {
		t.SetColor(Black.bright().bg()).Print(k[0])
		t.SetColor(Default).SetColor(Blue.bg()).Print(k[1])
		remain -= len(k[0]) + len(k[1])
	}
	t.Fill(remain)
	t.SetColor(Default).Write()
	return nil
}

func getProgramNameFromPID(pid uint32) string {
	path := fmt.Sprintf("/proc/%d/exe", pid)
	exePath, err := os.Readlink(path)
	if err != nil {
		// Not a running process
		return ""
	}
	return filepath.Base(exePath)
}
