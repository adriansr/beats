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
			name: "By accumulated overhead %",
			format: func(v float64) string {
				return fmt.Sprintf("%3.1f%%", v)
			},
			value: func(counter *auditd.Counter) float64 {
				if counter.TimeOut == 0 {
					return 0
				}
				return float64(counter.TimeIn) * 100.0 / float64(counter.TimeOut)
			},
		},
		{
			name: "By accumulated overhead time",
			format: func(v float64) string {
				return fmt.Sprintf("%s", time.Duration(v))
			},
			value: func(counter *auditd.Counter) float64 {
				return float64(counter.TimeIn)
			},
		},
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
				return float64(counter.TimeIn) * 100.0 / (float64(counter.TimeOut) * float64(counter.NumCalls))
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

func clearTermBelowCursor() {
	fmt.Print("\033[J")
}

func moveTo(row, col int) {
	fmt.Printf("\033[%d;%dH", row, col)
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

func (c Color) fg() {
	bright := ""
	if c&0x80 != 0 {
		bright = ";1"
		c &= 0x7f
	}
	fmt.Printf("\033[%d%sm", c, bright)
}

func (c Color) bg() {
	if c != Default {
		c += 10
	}
	c.fg()
}

func (c Color) bright() Color {
	return c | 0x80
}

func fill(n int) {
	for ; n > len(spaces); n -= len(spaces) {
		fmt.Print(spaces)
	}
	if n > 0 {
		fmt.Print(spaces[:n])
	}
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
			fmt.Sprintf("???(%d)", ct.SysNo)
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
		//fmt.Printf("[%s] (%s) calls:%d in:%s out:%s\r\n", syscallNames[ct.SysNo], sorter.format(sorter.value(ct)), ct.NumCalls, time.Duration(ct.TimeIn), time.Duration(ct.TimeOut))
	}

	// Clear the screen and move cursor to the top-left
	moveTo(0, 0)
	clearTermBelowCursor()
	Black.bg()
	Cyan.fg()
	fmt.Print("Syscalls: ")
	Cyan.bright().fg()
	fmt.Printf("%10d", len(counters))
	Default.fg()
	Cyan.fg()
	fmt.Print(" Trace events: ")
	Cyan.bright().fg()
	fmt.Printf("%10d", stats.Calls)
	Default.fg()
	Cyan.fg()
	fmt.Print(" Lost: ")
	Red.bright().fg()
	fmt.Printf("%10d\r\n", stats.Lost)
	//fmt.Printf("%d syscalls / %d events / %d lost\r\n", len(counters), stats.Calls, stats.Lost)

	Black.fg()
	White.bright().bg()
	const sortBy = " Sorted by: "
	fmt.Print(sortBy)
	Yellow.fg()
	Cyan.bright().bg()
	fmt.Print(sorter.name)
	fill(width - len(sorter.name) - len(sortBy))
	fmt.Print("\r\n")
	Black.bg()

	// Print table header
	Default.fg()
	Black.fg()
	Blue.bg()
	remain := width
	for idx, w := range widths {
		fill(w - len(columns[idx]))
		fmt.Print(columns[idx])
		remain -= w
	}
	fill(remain)
	fmt.Print("\r\n")
	Default.fg()
	for idx, row := range table {
		for col, w := range widths {
			fill(w - utf8.RuneCountInString(row[col]))
			fmt.Print(row[col])
		}
		fmt.Print(" ")
		if idx&1 != 0 {
			Green.bg()
		} else {
			Green.bg()
		}
		fill(int(float64(remain-1) * sorter.value(counters[idx]) / maxVal))
		Default.bg()
		fmt.Print("\r\n")
	}
	if excess > 0 {
		//fmt.Printf("[... and %d more ...]\r\n", excess)
	}
	moveTo(height, 0)
	remain = width
	for _, k := range keys {
		Black.bright().bg()
		fmt.Print(k[0])
		Default.fg()
		Blue.bg()
		fmt.Print(k[1])
		remain -= len(k[0]) + len(k[1])
	}
	fill(remain)
	Default.fg()
	return nil
}
