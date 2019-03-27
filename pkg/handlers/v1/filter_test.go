package v1

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/asecurityteam/logevent"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain/nexpose"
	"github.com/asecurityteam/runhttp"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestHandle(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockFilterer := NewMockVulnFilterer(ctrl)

	handler := NexposeVulnFilter{
		VulnerabilityFilter: mockFilterer,
		LogFn:               runhttp.LoggerFromContext,
	}

	mockFilterer.EXPECT().FilterVulnerabilities(gomock.Any()).Return([]nexpose.AssetVulnerabilityDetails{})

	input := &NexposeAssetVulnerabilities{
		Vulnerabilities: []nexpose.AssetVulnerabilityDetails{
			nexpose.AssetVulnerabilityDetails{
				VulnerabilityFinding: nexpose.VulnerabilityFinding{
					ID: "test",
				},
				Vulnerability: nexpose.Vulnerability{},
			},
		},
	}

	ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
	out, err := handler.Handle(ctx, input)
	require.Nil(t, err)
	require.Empty(t, out.Vulnerabilities)
}
