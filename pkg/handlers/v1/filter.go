package v1

import (
	"context"
	"time"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/filter"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/logs"
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

// NexposeVulnFilter accepts a payload with Nexpose asset information
// and a list of vulnerabilities and returns a payload of the same shape
// omitting vulnerabilities that do not meet the filter criteria
type NexposeVulnFilter struct {
	VulnerabilityFilterCriteria *filter.VulnerabilityFilterCriteria
	Producer                    domain.Producer
	LogFn                       domain.LogFn
	StatFn                      domain.StatFn
}

// Handle filters any AssetVulnerabilityDetails items from a given NexposeAssetVulnerabilitiesEvent
// that do not meet the filter criteria, produces the filtered AssetVulnerabilityDetailsEvent to a stream,
// and returns the filtered AssetVulnerabilityDetailsEvent, or an error if one occurred.
func (h NexposeVulnFilter) Handle(ctx context.Context, input NexposeAssetVulnerabilitiesEvent) (NexposeAssetVulnerabilitiesEvent, error) {
	filteredAssetVulnEvent := NexposeAssetVulnerabilitiesEvent{
		LastScanned:     input.LastScanned,
		Hostname:        input.Hostname,
		ID:              input.ID,
		IP:              input.IP,
		Vulnerabilities: h.FilterVulnerabilities(ctx, input),
	}
	_, err := h.Producer.Produce(ctx, filteredAssetVulnEvent)
	if err != nil {
		return NexposeAssetVulnerabilitiesEvent{}, err
	}
	return filteredAssetVulnEvent, nil
}

// FilterVulnerabilities returns a filtered list of vulnerabilities.
func (h NexposeVulnFilter) FilterVulnerabilities(ctx context.Context, assetVulnerabilities NexposeAssetVulnerabilitiesEvent) []AssetVulnerabilityDetails {
	logger := h.LogFn(ctx)
	stater := h.StatFn(ctx)

	minCvssV2Score := h.VulnerabilityFilterCriteria.CVSSV2MinimumScore
	vulnIDRegexp := h.VulnerabilityFilterCriteria.VulnIDRegexp

	filteredVulnerabilities := make([]AssetVulnerabilityDetails, 0)
	for _, vuln := range assetVulnerabilities.Vulnerabilities {
		if vuln.CvssV2Score > minCvssV2Score {
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnRetained,
				Method:  logs.CvssV2Score,
				VulnID:  vuln.ID,
				AssetID: assetVulnerabilities.ID,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		} else if vulnIDRegexp.MatchString(vuln.ID) {
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnRetained,
				Method:  logs.VulnID,
				VulnID:  vuln.ID,
				AssetID: assetVulnerabilities.ID,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		} else {
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnDiscarded,
				VulnID:  vuln.ID,
				AssetID: assetVulnerabilities.ID,
			})
			stater.Count("event.nexposevulnerability.filter.discarded", 1)
		}
	}
	return filteredVulnerabilities
}
