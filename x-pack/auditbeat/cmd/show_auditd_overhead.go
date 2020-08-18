// +build amd64,linux

package cmd

import (
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
	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
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
	auditdOverhead = &cobra.Command{
		Use:  "auditd-overhead",
		Long: "Show audit overhead on syscalls",
		RunE: runAuditOverhead,
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
			name: "Per-call overhead %",
			format: func(v float64) string {
				return fmt.Sprintf("%3.1f%%", v)
			},
			value: func(counter *auditd.Counter) float64 {
				if counter.TimeOut == 0 {
					return 0
				}
				return float64(counter.TimeIn) * 100.0 / (float64(counter.TimeOut))
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
	cmd.ShowCmd.AddCommand(auditdOverhead)
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

	auditCli, err := libaudit.NewAuditClient(nil)
	if err != nil {
		return errors.Wrap(err, "connecting to audit")
	}
	defer func() {
		if err := auditCli.Close(); err != nil {
			log.Errorf("Failed stopping audit client")
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

func (t *termBuffer) SetColor(c Color) *termBuffer {
	bright := ""
	if c&0x80 != 0 {
		bright = ";1"
		c &= 0x7f
	}
	return t.Printf("\033[%d%sm", c, bright)
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
	const fixedLines = 5
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
		name := syscallNames[ct.SysNo]
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
			fmt.Sprintf(" %s", format(ct.TimeOut)),
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
	t.SetColor(Green.bright()).Print("AUDIT  ").SetColor(Default)
	t.SetColor(Default).SetColor(Cyan).Print(" PID: ")
	if auditStatus.PID != 0 {
		t.SetColor(Cyan.bright()).Printf("%s", getProgramNameFromPID(auditStatus.PID))
		t.SetColor(Default).SetColor(Cyan).Printf("[%d]", auditStatus.PID)
	} else {
		t.SetColor(Cyan).Print("(none)")
	}
	t.SetColor(Default).SetColor(Cyan).Print(" Backlog: ")
	t.SetColor(Cyan.bright()).Printf("%5d", auditStatus.Backlog)
	t.SetColor(Default).SetColor(Cyan).Printf("/%-5d", auditStatus.BacklogLimit)
	t.SetColor(Default).SetColor(Cyan).Print(" Lost: ")
	t.SetColor(Red.bright()).Printf("%-10d\r\n", auditStatus.Lost).SetColor(Default)

	// Kprobes monitoring status line
	t.SetColor(Green.bright()).Print("KPROBES").SetColor(Default)
	t.SetColor(Default).SetColor(Cyan).Print(" Syscalls: ")
	t.SetColor(Cyan.bright()).Printf("%-10d", len(counters))
	t.SetColor(Default).SetColor(Cyan).Print(" Trace events: ")
	t.SetColor(Cyan.bright()).Printf("%-10d", stats.Calls)
	t.SetColor(Default).SetColor(Cyan).Print(" Dropped: ")
	t.SetColor(Red.bright()).Printf("%-10d\r\n", stats.Lost)

	// Sort line
	const sortBy = " Sorted by: "
	t.SetColor(Default).SetColor(White.bright().bg()).Print(sortBy)
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
