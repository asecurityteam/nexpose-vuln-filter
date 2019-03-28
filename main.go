package main

import (
	"context"
	"os"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/filter"
	v1 "github.com/asecurityteam/nexpose-vuln-filter/pkg/handlers/v1"
	"github.com/asecurityteam/runhttp"
	serverfull "github.com/asecurityteam/serverfull/pkg"
	serverfulldomain "github.com/asecurityteam/serverfull/pkg/domain"
	"github.com/asecurityteam/settings"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	ctx := context.Background()
	vulnFiltererComponent := &filter.VulnerabilityFiltererComponent{}
	vulnFilterer := new(filter.VulnerabilityFilterer)
	err = settings.NewComponent(ctx, source, vulnFiltererComponent, vulnFilterer)
	if err != nil {
		panic(err.Error())
	}

	handler := v1.NexposeVulnFilter{
		VulnerabilityFilter: vulnFilterer,
		LogFn:               runhttp.LoggerFromContext,
		StatFn:              runhttp.StatFromContext,
	}
	handlers := map[string]serverfulldomain.Handler{
		"filter": lambda.NewHandler(handler.Handle),
	}

	rt, err := serverfull.NewStatic(ctx, source, handlers)
	if err != nil {
		panic(err.Error())
	}
	if err := rt.Run(); err != nil {
		panic(err.Error())
	}
}
