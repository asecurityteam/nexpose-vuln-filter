package domain

import (
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain/nexpose"
)

// VulnFilterer is the expected form of filters applied to Nexpose vulnerabilities.
type VulnFilterer interface {
	FilterVulnerabilities([]nexpose.AssetVulnerabilityDetails) []nexpose.AssetVulnerabilityDetails
}
