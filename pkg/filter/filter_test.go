package filter

import (
	"context"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
)

func TestVulnFilterConfigName(t *testing.T) {
	config := &VulnerabilityFilterConfig{}
	require.Equal(t, config.Name(), "vulnerabilityfilter")
}

func TestVulnFilterComponentDefaultConfig(t *testing.T) {
	component := NewVulnerabilityFilterComponent()
	config := component.Settings()
	filter, err := component.New(context.Background(), config)
	require.Equal(t, filter.CVSSV2MinimumScore, 7.0)
	require.Equal(t, filter.VulnIDRegexp, regexp.MustCompile(".*"))
	require.NoError(t, err)
}

func TestFilterVulnerabilities(t *testing.T) {
	tests := []struct {
		name            string
		score           float64
		regex           string
		vulnerabilities []domain.Vulnerability
		expected        []domain.Vulnerability
	}{
		{
			"empty vuln list",
			7.0,
			".*",
			[]domain.Vulnerability{},
			[]domain.Vulnerability{},
		},
		{
			"filters out vulnerability that does not meet threshold or title regex",
			7.0,
			"bad-vuln-.*",
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:          "test-vuln-1",
					CvssV2Score: 6.0,
				},
			},
			[]domain.Vulnerability{},
		},
		{
			"does not filter out vulnerability that meets threshold but not regex",
			7.0,
			"bad-vuln-.*",
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:          "test-vuln-1",
					CvssV2Score: 8.0,
				},
			},
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:          "test-vuln-1",
					CvssV2Score: 8.0,
				},
			},
		},
		{
			"does not filter out vulnerability that meets regex but not threshold",
			7.0,
			"test-vuln-.*",
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:          "test-vuln-1",
					CvssV2Score: 4.0,
				},
			},
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:          "test-vuln-1",
					CvssV2Score: 4.0,
				},
			},
		},
		{
			"filters multiple vulnerabilities correctly",
			7.0,
			"bad-vuln-.*",
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:          "test-vuln-1",
					CvssV2Score: 5.0,
				},
				domain.Vulnerability{
					ID:          "test-vuln-2",
					CvssV2Score: 8.0,
				},
				domain.Vulnerability{
					ID:          "test-vuln-3",
					CvssV2Score: 9.0,
				},
				domain.Vulnerability{
					ID:          "bad-vuln-4",
					CvssV2Score: 4.0,
				},
			},
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:          "test-vuln-2",
					CvssV2Score: 8.0,
				},
				domain.Vulnerability{
					ID:          "test-vuln-3",
					CvssV2Score: 9.0,
				},
				domain.Vulnerability{
					ID:          "bad-vuln-4",
					CvssV2Score: 4.0,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			vulnFilter := &VulnerabilityFilter{
				CVSSV2MinimumScore: test.score,
				VulnIDRegexp:       regexp.MustCompile(test.regex),
				LogFn:              testLogFn,
				StatFn:             testStatFn,
			}

			asset := domain.Asset{
				ID: 1,
			}

			filteredVulnerabilities := vulnFilter.FilterVulnerabilities(context.Background(), asset, test.vulnerabilities)
			require.ElementsMatch(t, filteredVulnerabilities, test.expected)
		})
	}
}
