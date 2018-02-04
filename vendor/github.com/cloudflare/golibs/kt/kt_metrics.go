package kt

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TrackedConn is a wrapper around kt.Conn that will accept a prometheus counter
// vector, and keep track of number of IO operations made to KT.
type TrackedConn struct {
	kt      *Conn
	opTimer *prometheus.SummaryVec
}

const (
	opCount        = "COUNT"
	opRemove       = "REMOVE"
	opGetBulk      = "GETBULK"
	opGet          = "GET"
	opGetBytes     = "GETBYTES"
	opSet          = "SET"
	opGetBulkBytes = "GETBULKBYTES"
	opSetBulk      = "SETBULK"
	opRemoveBulk   = "REMOVEBULK"
	opMatchPrefix  = "MATCHPREFIX"
)

// NewTrackedConn creates a new connection to a Kyoto Tycoon endpoint, and tracks
// operations made to it using prometheus metrics.
// All supported operations are tracked, opTimer times the number of seconds
// each type of operation took, generating a summary.
func NewTrackedConn(host string, port int, poolsize int, timeout time.Duration,
	opTimer *prometheus.SummaryVec) (*TrackedConn, error) {
	conn, err := NewConn(host, port, poolsize, timeout)
	if err != nil {
		return nil, err
	}

	return &TrackedConn{
		kt:      conn,
		opTimer: opTimer}, nil
}

// NewTrackedConnFromConn returns a tracked connection that simply wraps the given
// database connection.
func NewTrackedConnFromConn(conn *Conn, opTimer *prometheus.SummaryVec) (*TrackedConn, error) {
	return &TrackedConn{
		kt:      conn,
		opTimer: opTimer}, nil
}

func (c *TrackedConn) Count() (int, error) {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opGet).Observe(since.Seconds())
	}()

	return c.kt.Count()
}

func (c *TrackedConn) Remove(key string) error {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opRemove).Observe(since.Seconds())
	}()

	return c.kt.Remove(key)
}

func (c *TrackedConn) GetBulk(keysAndVals map[string]string) error {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opGetBulk).Observe(since.Seconds())
	}()

	return c.kt.GetBulk(keysAndVals)
}

func (c *TrackedConn) Get(key string) (string, error) {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opGet).Observe(since.Seconds())
	}()

	return c.kt.Get(key)
}

func (c *TrackedConn) GetBytes(key string) ([]byte, error) {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opGetBytes).Observe(since.Seconds())
	}()

	return c.kt.GetBytes(key)
}

func (c *TrackedConn) Set(key string, value []byte) error {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opSet).Observe(since.Seconds())
	}()

	return c.kt.Set(key, value)
}

func (c *TrackedConn) GetBulkBytes(keys map[string][]byte) error {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opGetBulkBytes).Observe(since.Seconds())
	}()

	return c.kt.GetBulkBytes(keys)
}

func (c *TrackedConn) SetBulk(values map[string]string) (int64, error) {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opSetBulk).Observe(since.Seconds())
	}()

	return c.kt.SetBulk(values)
}

func (c *TrackedConn) RemoveBulk(keys []string) (int64, error) {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opRemoveBulk).Observe(since.Seconds())
	}()

	return c.kt.RemoveBulk(keys)
}

func (c *TrackedConn) MatchPrefix(key string, maxrecords int64) ([]string, error) {
	start := time.Now()
	defer func() {
		since := time.Since(start)
		c.opTimer.WithLabelValues(opMatchPrefix).Observe(since.Seconds())
	}()

	return c.kt.MatchPrefix(key, maxrecords)
}
