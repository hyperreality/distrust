package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type table struct {
	cols []string
	rows [][]string
}

func newTable(cols ...string) *table { return &table{cols: cols} }

func (t *table) add(cells ...string) { t.rows = append(t.rows, cells) }

// print aligns columns, ignoring ANSI color codes when measuring.
func (t *table) print(w io.Writer) {
	width := make([]int, len(t.cols))
	all := append([][]string{t.cols}, t.rows...)
	for _, r := range all {
		for i, c := range r {
			if i < len(width) && visible(c) > width[i] {
				width[i] = visible(c)
			}
		}
	}
	for _, r := range all {
		var b strings.Builder
		for i, c := range r {
			b.WriteString(c)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", width[i]-visible(c)+2))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}

func visible(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == '\x1b':
			esc = true
		case esc && r == 'm':
			esc = false
		case !esc:
			n++
		}
	}
	return n
}

var useColor = func() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func colorTrust(s string) string {
	if !useColor {
		return s
	}
	code := ""
	switch strings.TrimPrefix(s, "-") {
	case "trusted", "UNMANAGED", "error":
		code = "31" // red: a blocked CA is still trusted
	case "distrusted", "available":
		code = "32"
	case "absent":
		code = "36"
	case "unsupported", "unknown":
		code = "33"
	default:
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fail(err)
	}
	return exitOK
}
