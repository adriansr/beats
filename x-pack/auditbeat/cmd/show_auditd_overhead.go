// +build amd64,linux

package cmd

import (
	"fmt"
	"os"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/elastic/beats/v7/auditbeat/cmd"
	"github.com/elastic/beats/v7/auditbeat/module/auditd"
	"github.com/elastic/beats/v7/libbeat/logp"
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
				return fmt.Sprintf("%s", time.Duration(v))
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
				return fmt.Sprintf("%s", time.Duration(v))
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

	// Enter "alternate screen"
	fmt.Print("\033[?1049h")
	// Leave alternate screen on termination
	defer fmt.Print("\033[?1049l")

	timerC := time.Tick(time.Second)
	paused := false
	for {
		forceUpdate := false
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
			}

		case <-timerC:
		}
		if !paused || forceUpdate {
			if err := display(monitor.Stats()); err != nil {
				panic(err)
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
	{"[P]", "Pause"},
}

func display(stats auditd.Stats) error {
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
	if limit > height-4 {
		limit = height - 4
		excess = len(counters) - limit
	}
	var table = make([][]string, limit)
	var widths = make([]int, len(columns))
	for idx, col := range columns {
		widths[idx] = len(col)
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
			fmt.Sprintf(" %s", time.Duration(ct.TimeOut)),
			fmt.Sprintf(" %s", time.Duration(ct.TimeIn)),
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
	// Status line
	t.SetColor(Black.bg()).SetColor(Cyan).Print("Syscalls: ")
	t.SetColor(Cyan.bright()).Printf("%10d", len(counters))
	t.SetColor(Default).SetColor(Cyan).Print(" Trace events: ")
	t.SetColor(Cyan.bright()).Printf("%10d", stats.Calls)
	t.SetColor(Default).SetColor(Cyan).Print(" Lost: ")
	t.SetColor(Red.bright()).Printf("%10d\r\n", stats.Lost)

	const sortBy = " Sorted by: "
	t.SetColor(Black).SetColor(White.bright().bg()).Print(sortBy)
	t.SetColor(Yellow).SetColor(Cyan.bright().bg()).Print(sorter.name)
	t.Fill(width - len(sorter.name) - len(sortBy)).CRLF()

	// Print table header
	t.SetColor(Default).SetColor(Black).SetColor(Blue.bg())
	remain := width
	for idx, w := range widths {
		t.Fill(w - len(columns[idx])).Print(columns[idx])
		remain -= w
	}
	t.Fill(remain).CRLF()
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
		t.Fill(int(float64(remain-1) * sorter.value(counters[idx]) / maxVal))
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
