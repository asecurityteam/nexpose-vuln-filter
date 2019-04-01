package v1

import (
	"context"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain/nexpose"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/filter"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/logs"
)

// NexposeAssetVulnerabilities is a Nexpose asset response payload appended
// with assetVulnerabilityDetails
type NexposeAssetVulnerabilities struct {
	nexpose.Asset
	Vulnerabilities []nexpose.AssetVulnerabilityDetails `json:"assetVulnerabilityDetails"`
}

// NexposeVulnFilter accepts a payload with Nexpose asset information
// and a list of vulnerabilities and returns a payload of the same shape
// omitting vulnerabilities that do not meet the filter criteria
type NexposeVulnFilter struct {
	VulnerabilityFilterCriteria *filter.VulnerabilityFilterCriteria
	LogFn                       domain.LogFn
	StatFn                      domain.StatFn
}

// Handle filters an asset's vulnerabilities based on predefined criteria and returns
// the payload without vulnerabilities that meet the requirements
func (h NexposeVulnFilter) Handle(ctx context.Context, input NexposeAssetVulnerabilities) (NexposeAssetVulnerabilities, error) {
	output := NexposeAssetVulnerabilities{
		Asset:           input.Asset,
		Vulnerabilities: h.FilterVulnerabilities(ctx, input),
	}
	return output, nil
}

// FilterVulnerabilities returns a filtered list of vulnerabilities.
func (h NexposeVulnFilter) FilterVulnerabilities(ctx context.Context, assetVulnerabilities NexposeAssetVulnerabilities) []nexpose.AssetVulnerabilityDetails {
	logger := h.LogFn(ctx)
	stater := h.StatFn(ctx)

	minCvssV2Score := h.VulnerabilityFilterCriteria.CVSSV2MinimumScore
	vulnIDRegexp := h.VulnerabilityFilterCriteria.VulnIDRegexp

	filteredVulnerabilities := make([]nexpose.AssetVulnerabilityDetails, 0)
	for _, vuln := range assetVulnerabilities.Vulnerabilities {
		if vuln.Vulnerability.Cvss.V2.Score > minCvssV2Score {
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnRetained,
				Method:  logs.CvssV2Score,
				VulnID:  vuln.Vulnerability.ID,
				AssetID: assetVulnerabilities.ID,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		} else if vulnIDRegexp.MatchString(vuln.Vulnerability.ID) {
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnRetained,
				Method:  logs.VulnID,
				VulnID:  vuln.Vulnerability.ID,
				AssetID: assetVulnerabilities.ID,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		} else {
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnDiscarded,
				VulnID:  vuln.Vulnerability.ID,
				AssetID: assetVulnerabilities.ID,
			})
			stater.Count("event.nexposevulnerability.filter.discarded", 1)
		}
	}
	return filteredVulnerabilities
}
