package main

import (
	"context"
	"os"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/filter"
	v1 "github.com/asecurityteam/nexpose-vuln-filter/pkg/handlers/v1"
	"github.com/asecurityteam/runhttp"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

func main() {
	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	ctx := context.Background()
	vulnFilterComponent := &filter.VulnerabilityFilterComponent{}
	vulnFilterCriteria := new(filter.VulnerabilityFilterCriteria)
	err = settings.NewComponent(ctx, source, vulnFilterComponent, vulnFilterCriteria)
	if err != nil {
		panic(err.Error())
	}

	handler := v1.NexposeVulnFilter{
		VulnerabilityFilterCriteria: vulnFilterCriteria,
		LogFn:                       runhttp.LoggerFromContext,
		StatFn:                      runhttp.StatFromContext,
	}
	handlers := map[string]serverfull.Function{
		"filter": serverfull.NewFunction(handler.Handle),
	}

	fetcher := &serverfull.StaticFetcher{Functions: handlers}
	if err := serverfull.Start(ctx, source, fetcher); err != nil {
		panic(err.Error())
	}
}
