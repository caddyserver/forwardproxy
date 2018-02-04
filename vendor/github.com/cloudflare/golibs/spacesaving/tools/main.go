package main

import (
	"bufio"
	"fmt"
	"github.com/cloudflare/golibs/spacesaving"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const TimeFormatString = "2006-01-02 15:04:05.999999999 -0700 MST"
const halfLife = 60 * time.Second

func main() {
	ss := spacesaving.Rate{}

	slots, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		panic(err)
	}

	ss.Init(uint32(slots), halfLife)

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

		ss.Touch(key, ts)
		lastTime = ts
	}

	elements := ss.GetAll(lastTime)
	for _, e := range elements {
		fmt.Printf("%s, %f, %f\n", e.Key, e.LoRate, e.HiRate)
	}
}
