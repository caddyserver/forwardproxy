package main

import (
	"bufio"
	"fmt"
	"github.com/cloudflare/golibs/ewma"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type Element struct {
	Key  string
	Rate float64
}

type elslice []Element

func (a elslice) Len() int           { return len(a) }
func (a elslice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a elslice) Less(i, j int) bool { return a[i].Rate < a[j].Rate }

const TimeFormatString = "2006-01-02 15:04:05.999999999 -0700 MST"
const halfLife = 60 * time.Second

func main() {
	m := make(map[string]*ewma.EwmaRate, 4096)

	var lastTime time.Time

	in := bufio.NewReader(os.Stdin)
	for lineno := 1; true; lineno += 1 {
		line, err := in.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ",", 2)

		ts, err := time.Parse(TimeFormatString, parts[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ignoring line %d: %v\n",
				lineno, err)
			continue
		}
		key := strings.TrimSpace(parts[1])

		if rate, found := m[key]; found {
			rate.Update(ts)
		} else {
			rate = new(ewma.EwmaRate)
			rate.Init(halfLife)
			rate.Update(ts)
			m[key] = rate
		}
		lastTime = ts
	}

	elements := make([]Element, 0, len(m))
	for key, rate := range m {
		elements = append(elements, Element{
			key,
			rate.Current(lastTime),
		})
	}

	sort.Sort(sort.Reverse(elslice(elements)))

	for _, e := range elements {
		fmt.Printf("%s, %f\n", e.Key, e.Rate)
	}
}
