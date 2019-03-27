package domain

import (
	"fmt"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain/nexpose"
)

// VulnFilterer is the expected form of filters applied to Nexpose vulnerabilities.
type VulnFilterer interface {
	FilterVulnerabilities([]nexpose.AssetVulnerabilityDetails) []nexpose.AssetVulnerabilityDetails
}

// ErrInvalidInput indicates that the Vulnerability did not have the expected shape.
type ErrInvalidInput struct {
	Reason string
}

func (e ErrInvalidInput) Error() string {
	return fmt.Sprintf("invalid input: %s", e.Reason)
}
