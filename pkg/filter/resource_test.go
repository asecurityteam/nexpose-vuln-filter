package filter

import (
	"context"
	"testing"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain/nexpose"
	"github.com/stretchr/testify/require"
)

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
			vulnFiltererComponent := &VulnerabilityFiltererComponent{}
			vulnFilterer, err := vulnFiltererComponent.New(context.Background(), &VulnerabilityFiltererConfig{
				CVSSV2MinimumScore: test.score,
				VulnIDRegexMatch:   test.regex,
			})

			require.Nil(t, err)

			filteredVulnerabilities := vulnFilterer.FilterVulnerabilities(test.vulnerabilities)
			require.ElementsMatch(t, filteredVulnerabilities, test.expected)
		})
	}
}

func TestVulnFiltererConfigName(t *testing.T) {
	config := &VulnerabilityFiltererConfig{}
	require.Equal(t, config.Name(), "VulnerabilityFilter")
}

func TestVulnFiltererComponentDefaultConfig(t *testing.T) {
	component := &VulnerabilityFiltererComponent{}
	config := component.Settings()
	require.Equal(t, config.CVSSV2MinimumScore, 7.0)
	require.Equal(t, config.VulnIDRegexMatch, ".*")
}
