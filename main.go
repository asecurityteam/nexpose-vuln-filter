package main

import (
	"context"
	"os"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/filter"
	v1 "github.com/asecurityteam/nexpose-vuln-filter/pkg/handlers/v1"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

type config struct {
	VulnerabilityFilter *filter.VulnerabilityFilterConfig
	LambdaMode          bool `description:"Use the Lambda SDK to start the system."`
}

func (*config) Name() string {
	return "nexposevulnfilter"
}

type component struct {
	VulnerabilityFilter *filter.VulnerabilityFilterComponent
}

func newComponent() *component {
	return &component{
		VulnerabilityFilter: filter.NewVulnerabilityFilterComponent(),
	}
}

func (c *component) Settings() *config {
	return &config{
		VulnerabilityFilter: c.VulnerabilityFilter.Settings(),
	}
}

func (c *component) New(ctx context.Context, conf *config) (func(context.Context, settings.Source) error, error) {
	f, err := c.VulnerabilityFilter.New(ctx, conf.VulnerabilityFilter)
	if err != nil {
		return nil, err
	}

	filterHandler := &v1.NexposeVulnFilter{
		LogFn:                       domain.LoggerFromContext,
		StatFn:                      domain.StatFromContext,
		VulnerabilityFilterCriteria: f,
	}
	handlers := map[string]serverfull.Function{
		"filter": serverfull.NewFunction(filterHandler.Handle),
	}
	fetcher := &serverfull.StaticFetcher{Functions: handlers}
	if conf.LambdaMode {
		return func(ctx context.Context, source settings.Source) error {
			return serverfull.StartLambda(ctx, source, fetcher, "filter")
		}, nil
	}
	return func(ctx context.Context, source settings.Source) error {
		return serverfull.StartHTTP(ctx, source, fetcher)
	}, nil
}

func main() {
	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	ctx := context.Background()
	runner := new(func(context.Context, settings.Source) error)
	cmp := newComponent()
	err = settings.NewComponent(ctx, source, cmp, runner)
	if err != nil {
		panic(err.Error())
	}
	if err := (*runner)(ctx, source); err != nil {
		panic(err.Error())
	}
}
