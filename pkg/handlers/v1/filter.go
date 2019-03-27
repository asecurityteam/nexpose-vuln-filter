package v1

import (
	"context"
	"fmt"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain/nexpose"
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
	VulnerabilityFilter domain.VulnFilterer
	LogFn               domain.LogFn
}

// Handle filters an asset's vulnerabilities based on predefined criteria and returns
// the payload without vulnerabilities that meet the requirements
func (h NexposeVulnFilter) Handle(ctx context.Context, input *NexposeAssetVulnerabilities) (*NexposeAssetVulnerabilities, error) {
	logger := h.LogFn(ctx)
	initialNumberOfVulns := len(input.Vulnerabilities)
	input.Vulnerabilities = h.VulnerabilityFilter.FilterVulnerabilities(input.Vulnerabilities)
	logger.Info(fmt.Sprintf("Filtered %d vulnerabilities to %d for asset: %d", initialNumberOfVulns, len(input.Vulnerabilities), input.ID))
	return input, nil
}
