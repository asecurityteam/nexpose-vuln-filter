package v1

import (
	"context"
	"errors"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
)

func TestHandle(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	input := NexposeAssetVulnerabilitiesEvent{
		ID: 123,
		Vulnerabilities: []AssetVulnerabilityDetails{
			AssetVulnerabilityDetails{
				ID:          "test",
				CvssV2Score: 6.0,
			},
		},
	}

	output := NexposeAssetVulnerabilitiesEvent{
		ID:              input.ID,
		Vulnerabilities: []AssetVulnerabilityDetails{},
	}

	asset := domain.Asset{
		ID: input.ID,
	}
	vulns := []domain.Vulnerability{
		domain.Vulnerability{
			ID:          "test",
			CvssV2Score: 6.0,
			Results:     make([]domain.AssessmentResult, 0),
		},
	}

	mockFilter := NewMockVulnerabilityFilter(ctrl)
	mockFilter.EXPECT().FilterVulnerabilities(gomock.Any(), asset, vulns).Return([]domain.Vulnerability{})

	mockProducer := NewMockProducer(ctrl)
	mockProducer.EXPECT().Produce(gomock.Any(), output).Return(nil, nil)

	handler := FilterHandler{
		VulnerabilityFilter: mockFilter,
		Producer:            mockProducer,
		LogFn:               testLogFn,
		StatFn:              testStatFn,
	}

	out, err := handler.Handle(context.Background(), input)
	require.Nil(t, err)
	require.Empty(t, out.Vulnerabilities)
}

func TestHandleProducerError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	input := NexposeAssetVulnerabilitiesEvent{
		ID: 123,
		Vulnerabilities: []AssetVulnerabilityDetails{
			AssetVulnerabilityDetails{
				ID:          "test",
				CvssV2Score: 6.0,
			},
		},
	}

	output := NexposeAssetVulnerabilitiesEvent{
		ID:              input.ID,
		Vulnerabilities: []AssetVulnerabilityDetails{},
	}

	asset := domain.Asset{
		ID: input.ID,
	}
	vulns := []domain.Vulnerability{
		domain.Vulnerability{
			ID:          "test",
			CvssV2Score: 6.0,
			Results:     make([]domain.AssessmentResult, 0),
		},
	}

	mockFilter := NewMockVulnerabilityFilter(ctrl)
	mockFilter.EXPECT().FilterVulnerabilities(gomock.Any(), asset, vulns).Return([]domain.Vulnerability{})

	mockProducer := NewMockProducer(ctrl)
	mockProducer.EXPECT().Produce(gomock.Any(), output).Return(nil, errors.New(""))

	handler := FilterHandler{
		VulnerabilityFilter: mockFilter,
		Producer:            mockProducer,
		LogFn:               testLogFn,
		StatFn:              testStatFn,
	}

	out, err := handler.Handle(context.Background(), input)
	require.Error(t, err)
	require.Empty(t, out.Vulnerabilities)
}

func TestVulnDetailsToVuln(t *testing.T) {
	tests := []struct {
		name          string
		vulnDetails   []AssetVulnerabilityDetails
		expectedVulns []domain.Vulnerability
	}{
		{
			"empty AssetVulnerabilityDetails",
			[]AssetVulnerabilityDetails{},
			[]domain.Vulnerability{},
		},
		{
			"empty Results",
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:      "foo",
					Results: []AssessmentResult{},
				},
			},
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:      "foo",
					Results: make([]domain.AssessmentResult, 0),
				},
			},
		},
		{
			"AssetVulnerabilityDetails with Results",
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID: "foo",
					Results: []AssessmentResult{
						AssessmentResult{
							Port:     80,
							Protocol: "HTTP",
							Proof:    "This is proof.",
						},
					},
				},
			},
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID: "foo",
					Results: []domain.AssessmentResult{
						domain.AssessmentResult{
							Port:     80,
							Protocol: "HTTP",
							Proof:    "This is proof.",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			vulns := vulnDetailsToVuln(test.vulnDetails)
			require.ElementsMatch(t, vulns, test.expectedVulns)
		})
	}
}

func TestVulnToVulnDetails(t *testing.T) {
	tests := []struct {
		name                string
		vulns               []domain.Vulnerability
		expectedVulnDetails []AssetVulnerabilityDetails
	}{
		{
			"empty AssetVulnerabilityDetails",
			[]domain.Vulnerability{},
			[]AssetVulnerabilityDetails{},
		},
		{
			"empty Results",
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID:      "foo",
					Results: make([]domain.AssessmentResult, 0),
				},
			},
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID:      "foo",
					Results: []AssessmentResult{},
				},
			},
		},
		{
			"AssetVulnerabilityDetails with Results",
			[]domain.Vulnerability{
				domain.Vulnerability{
					ID: "foo",
					Results: []domain.AssessmentResult{
						domain.AssessmentResult{
							Port:     80,
							Protocol: "HTTP",
							Proof:    "This is proof.",
						},
					},
				},
			},
			[]AssetVulnerabilityDetails{
				AssetVulnerabilityDetails{
					ID: "foo",
					Results: []AssessmentResult{
						AssessmentResult{
							Port:     80,
							Protocol: "HTTP",
							Proof:    "This is proof.",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			vulns := vulnToVulnDetails(test.vulns)
			require.ElementsMatch(t, vulns, test.expectedVulnDetails)
		})
	}
}
