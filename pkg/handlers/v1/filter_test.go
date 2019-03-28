package v1

import (
	"context"
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/asecurityteam/logevent"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain/nexpose"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/filter"
	"github.com/asecurityteam/runhttp"
	"github.com/stretchr/testify/require"
)

func TestHandle(t *testing.T) {
	handler := NexposeVulnFilter{
		VulnerabilityFilter: filter.VulnerabilityFilterer{CVSSV2MinimumScore: 7.0, VulnIDRegexp: regexp.MustCompile("bad-.*")},
		LogFn:               runhttp.LoggerFromContext,
		StatFn:              runhttp.StatFromContext,
	}

	input := &NexposeAssetVulnerabilities{
		Vulnerabilities: []nexpose.AssetVulnerabilityDetails{
			nexpose.AssetVulnerabilityDetails{
				VulnerabilityFinding: nexpose.VulnerabilityFinding{
					ID: "test",
				},
				Vulnerability: nexpose.Vulnerability{
					Cvss: &nexpose.VulnerabilityCvss{
						V2: &nexpose.VulnerabilityCvssV2{
							Score: 6.0,
						},
					},
				},
			},
		},
	}

	ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
	out, err := handler.Handle(ctx, input)
	require.Nil(t, err)
	require.Empty(t, out.Vulnerabilities)
}

func TestVulnFilterer(t *testing.T) {
	tests := []struct {
		name            string
		score           float64
		regex           string
		vulnerabilities []nexpose.AssetVulnerabilityDetails
		expected        []nexpose.AssetVulnerabilityDetails
	}{
		{
			"empty vuln list",
			7.0,
			".*",
			[]nexpose.AssetVulnerabilityDetails{},
			[]nexpose.AssetVulnerabilityDetails{},
		},
		{
			"filters out vulnerability that does not meet threshold or title regex",
			7.0,
			"bad-vuln-.*",
			[]nexpose.AssetVulnerabilityDetails{
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-1",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 6.0,
							},
						},
					},
				},
			},
			[]nexpose.AssetVulnerabilityDetails{},
		},
		{
			"does not filter out vulnerability that meets threshold but not regex",
			7.0,
			"bad-vuln-.*",
			[]nexpose.AssetVulnerabilityDetails{
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-1",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 8.0,
							},
						},
					},
				},
			},
			[]nexpose.AssetVulnerabilityDetails{
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-1",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 8.0,
							},
						},
					},
				},
			},
		},
		{
			"does not filter out vulnerability that meets regex but not threshold",
			7.0,
			"test-vuln-.*",
			[]nexpose.AssetVulnerabilityDetails{
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-1",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 4.0,
							},
						},
					},
				},
			},
			[]nexpose.AssetVulnerabilityDetails{
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-1",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 4.0,
							},
						},
					},
				},
			},
		},
		{
			"filters multiple vulnerabilities correctly",
			7.0,
			"bad-vuln-.*",
			[]nexpose.AssetVulnerabilityDetails{
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-1",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 5.0,
							},
						},
					},
				},
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-2",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 8.0,
							},
						},
					},
				},
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-3",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 9.0,
							},
						},
					},
				},
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "bad-vuln-4",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 4.0,
							},
						},
					},
				},
			},
			[]nexpose.AssetVulnerabilityDetails{
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-2",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 8.0,
							},
						},
					},
				},
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "test-vuln-3",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 9.0,
							},
						},
					},
				},
				nexpose.AssetVulnerabilityDetails{
					Vulnerability: nexpose.Vulnerability{
						ID: "bad-vuln-4",
						Cvss: &nexpose.VulnerabilityCvss{
							V2: &nexpose.VulnerabilityCvssV2{
								Score: 4.0,
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			vulnFilterer := filter.VulnerabilityFilterer{
				CVSSV2MinimumScore: test.score,
				VulnIDRegexp:       regexp.MustCompile(test.regex),
			}
			handler := NexposeVulnFilter{
				VulnerabilityFilter: vulnFilterer,
				LogFn:               runhttp.LoggerFromContext,
				StatFn:              runhttp.StatFromContext,
			}

			assetVulnerabilities := &NexposeAssetVulnerabilities{
				Vulnerabilities: test.vulnerabilities,
			}

			ctx := logevent.NewContext(context.Background(), logevent.New(logevent.Config{Output: ioutil.Discard}))
			filteredVulnerabilities := handler.FilterVulnerabilities(ctx, assetVulnerabilities)
			require.ElementsMatch(t, filteredVulnerabilities, test.expected)
		})
	}
}
