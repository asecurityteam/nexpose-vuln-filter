package v1

import (
	"context"
	"time"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
)

// NexposeAssetVulnerabilitiesEvent is a Nexpose asset response payload appended
// with assetVulnerabilityDetails
type NexposeAssetVulnerabilitiesEvent struct {
	LastScanned     time.Time                   `json:"lastScanned"`
	Hostname        string                      `json:"hostname"`
	ID              int64                       `json:"id"`
	IP              string                      `json:"ip"`
	Vulnerabilities []AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
}

// AssetVulnerabilityDetails contains the vulnerability information
type AssetVulnerabilityDetails struct {
	ID             string             `json:"id"`
	Results        []AssessmentResult `json:"results"`
	CvssV2Score    float64            `json:"cvssV2Score"`
	CvssV2Severity string             `json:"cvssV2Severity"`
	Description    string             `json:"description"`
	Title          string             `json:"title"`
	Solutions      []string           `json:"solutions"`
}

// AssessmentResult contains port and protocol information for the vulnerability
type AssessmentResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// FilterHandler accepts a payload with Nexpose asset information
// and a list of vulnerabilities and returns a payload of the same shape
// omitting vulnerabilities that do not meet the filter criteria
type FilterHandler struct {
	VulnerabilityFilter domain.VulnerabilityFilter
	Producer            domain.Producer
	LogFn               domain.LogFn
	StatFn              domain.StatFn
}

// Handle filters any AssetVulnerabilityDetails items from a given NexposeAssetVulnerabilitiesEvent
// that do not meet the filter criteria, produces the filtered AssetVulnerabilityDetailsEvent to a stream,
// and returns the filtered AssetVulnerabilityDetailsEvent, or an error if one occurred.
func (h FilterHandler) Handle(ctx context.Context, input NexposeAssetVulnerabilitiesEvent) (NexposeAssetVulnerabilitiesEvent, error) {
	asset := domain.Asset{
		ID:          input.ID,
		IP:          input.IP,
		Hostname:    input.Hostname,
		LastScanned: input.LastScanned,
	}
	vulns := vulnDetailsToVuln(input.Vulnerabilities)
	vulns = h.VulnerabilityFilter.FilterVulnerabilities(ctx, asset, vulns)
	vulnDetails := vulnToVulnDetails(vulns)

	filteredAssetVulnEvent := NexposeAssetVulnerabilitiesEvent{
		LastScanned:     input.LastScanned,
		Hostname:        input.Hostname,
		ID:              input.ID,
		IP:              input.IP,
		Vulnerabilities: vulnDetails,
	}
	_, err := h.Producer.Produce(ctx, filteredAssetVulnEvent)
	if err != nil {
		return NexposeAssetVulnerabilitiesEvent{}, err
	}
	return filteredAssetVulnEvent, nil
}

func vulnDetailsToVuln(vulnDetails []AssetVulnerabilityDetails) []domain.Vulnerability {
	vulns := make([]domain.Vulnerability, len(vulnDetails))
	for vulnOffset, vulnDetail := range vulnDetails {
		results := make([]domain.AssessmentResult, len(vulnDetail.Results))
		for resultOffset, result := range vulnDetail.Results {
			results[resultOffset] = domain.AssessmentResult(result)
		}
		vulns[vulnOffset] = domain.Vulnerability{
			ID:             vulnDetail.ID,
			Results:        results,
			CvssV2Score:    vulnDetail.CvssV2Score,
			CvssV2Severity: vulnDetail.CvssV2Severity,
			Description:    vulnDetail.Description,
			Title:          vulnDetail.Title,
			Solutions:      vulnDetail.Solutions,
		}
	}
	return vulns
}

func vulnToVulnDetails(vulns []domain.Vulnerability) []AssetVulnerabilityDetails {
	vulnDetails := make([]AssetVulnerabilityDetails, len(vulns))
	for vulnOffset, vuln := range vulns {
		results := make([]AssessmentResult, len(vuln.Results))
		for resultOffset, result := range vuln.Results {
			results[resultOffset] = AssessmentResult(result)
		}
		vulnDetails[vulnOffset] = AssetVulnerabilityDetails{
			ID:             vuln.ID,
			Results:        results,
			CvssV2Score:    vuln.CvssV2Score,
			CvssV2Severity: vuln.CvssV2Severity,
			Description:    vuln.Description,
			Title:          vuln.Title,
			Solutions:      vuln.Solutions,
		}
	}
	return vulnDetails
}
