package v1

import (
	"context"
	"time"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
)

type nopStat struct{}

func (*nopStat) Gauge(stat string, value float64, tags ...string)        {}
func (*nopStat) Count(stat string, count float64, tags ...string)        {}
func (*nopStat) Histogram(stat string, value float64, tags ...string)    {}
func (*nopStat) Timing(stat string, value time.Duration, tags ...string) {}
func (*nopStat) AddTags(tags ...string)                                  {}
func (*nopStat) GetTags() []string {
	return []string{}
}

func testStatFn(context.Context) domain.Stat { return &nopStat{} }
