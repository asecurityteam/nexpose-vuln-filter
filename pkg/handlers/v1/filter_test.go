package v1

import (
	"context"
	"errors"
	"regexp"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/filter"
)

func TestHandle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	input := NexposeAssetVulnerabilitiesEvent{
		Vulnerabilities: []AssetVulnerabilityDetails{
			AssetVulnerabilityDetails{
				ID:          "test",
				CvssV2Score: 6.0,
			},
		},
	}

	output := NexposeAssetVulnerabilitiesEvent{
		Vulnerabilities: []AssetVulnerabilityDetails{},
	}

	mockProducer := NewMockProducer(ctrl)
	mockProducer.EXPECT().Produce(gomock.Any(), output).Return(nil, nil)

	handler := NexposeVulnFilter{
		VulnerabilityFilterCriteria: &filter.VulnerabilityFilterCriteria{
			CVSSV2MinimumScore: 7.0,
			VulnIDRegexp:       regexp.MustCompile("bad-.*"),
		},
		LogFn:    testLogFn,
		StatFn:   testStatFn,
		Producer: mockProducer,
	}

	out, err := handler.Handle(context.Background(), input)
	require.Nil(t, err)
	require.Empty(t, out.Vulnerabilities)
}

func TestHandleProducerError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	input := NexposeAssetVulnerabilitiesEvent{
		Vulnerabilities: []AssetVulnerabilityDetails{
			AssetVulnerabilityDetails{
				ID:          "test",
				CvssV2Score: 6.0,
			},
		},
	}

	output := NexposeAssetVulnerabilitiesEvent{
		Vulnerabilities: []AssetVulnerabilityDetails{},
	}

	mockProducer := NewMockProducer(ctrl)
	mockProducer.EXPECT().Produce(gomock.Any(), output).Return(nil, errors.New(""))

	handler := NexposeVulnFilter{
		VulnerabilityFilterCriteria: &filter.VulnerabilityFilterCriteria{
			CVSSV2MinimumScore: 7.0,
			VulnIDRegexp:       regexp.MustCompile("bad-.*"),
		},
		LogFn:    testLogFn,
		StatFn:   testStatFn,
		Producer: mockProducer,
	}

	out, err := handler.Handle(context.Background(), input)
	require.Error(t, err)
	require.Empty(t, out.Vulnerabilities)
}

func TestVulnFilterer(t *testing.T) {
	tests := []struct {
		name            string
		score           float64
		regex           string
		vulnerabilities []AssetVulnerabilityDetails
		expected        []AssetVulnerabilityDetails
	}{
		{
			"empty vuln list",
			7.0,
			".*",
			[]AssetVulnerabilityDetails{},
			[]AssetVulnerabilityDetails{},
		},
		{
			"filters out vulnerability that does not meet threshold or title regex",
			7.0,
			"bad-vuln-.*",
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:          "test-vuln-1",
					CvssV2Score: 6.0,
				},
			},
			[]AssetVulnerabilityDetails{},
		},
		{
			"does not filter out vulnerability that meets threshold but not regex",
			7.0,
			"bad-vuln-.*",
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:          "test-vuln-1",
					CvssV2Score: 8.0,
				},
			},
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:          "test-vuln-1",
					CvssV2Score: 8.0,
				},
			},
		},
		{
			"does not filter out vulnerability that meets regex but not threshold",
			7.0,
			"test-vuln-.*",
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:          "test-vuln-1",
					CvssV2Score: 4.0,
				},
			},
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:          "test-vuln-1",
					CvssV2Score: 4.0,
				},
			},
		},
		{
			"filters multiple vulnerabilities correctly",
			7.0,
			"bad-vuln-.*",
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:          "test-vuln-1",
					CvssV2Score: 5.0,
				},
				AssetVulnerabilityDetails{
					ID:          "test-vuln-2",
					CvssV2Score: 8.0,
				},
				AssetVulnerabilityDetails{
					ID:          "test-vuln-3",
					CvssV2Score: 9.0,
				},
				AssetVulnerabilityDetails{
					ID:          "bad-vuln-4",
					CvssV2Score: 4.0,
				},
			},
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:          "test-vuln-2",
					CvssV2Score: 8.0,
				},
				AssetVulnerabilityDetails{
					ID:          "test-vuln-3",
					CvssV2Score: 9.0,
				},
				AssetVulnerabilityDetails{
					ID:          "bad-vuln-4",
					CvssV2Score: 4.0,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			vulnFilterCriteria := &filter.VulnerabilityFilterCriteria{
				CVSSV2MinimumScore: test.score,
				VulnIDRegexp:       regexp.MustCompile(test.regex),
			}

			handler := NexposeVulnFilter{
				VulnerabilityFilterCriteria: vulnFilterCriteria,
				LogFn:                       testLogFn,
				StatFn:                      testStatFn,
			}

			assetVulnerabilities := NexposeAssetVulnerabilitiesEvent{
				Vulnerabilities: test.vulnerabilities,
			}

			filteredVulnerabilities := handler.FilterVulnerabilities(context.Background(), assetVulnerabilities)
			require.ElementsMatch(t, filteredVulnerabilities, test.expected)
		})
	}
}
