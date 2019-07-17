package filter

import (
	"context"
	"regexp"
)

// VulnerabilityFilterConfig defines the configuration options for a VulnerabilityFilterCriteria.
type VulnerabilityFilterConfig struct {
	CVSSV2MinimumScore float64 `description:"The minimum CVSS V2 score threshold for vulnerabilties to further process."`
	VulnIDRegexMatch   string  `description:"A regex to match the vulnerability ID to include for further processing."`
}

// Name is used by the settings library to replace the default naming convention.
func (v *VulnerabilityFilterConfig) Name() string {
	return "vulnerabilityfilter"
}

// VulnerabilityFilterComponent satisfies the settings library Component API,
// and may be used by the settings.NewComponent function.
type VulnerabilityFilterComponent struct{}

// NewVulnerabilityFilterComponent generates a VulnerabilityFilterComponent.
func NewVulnerabilityFilterComponent() *VulnerabilityFilterComponent {
	return &VulnerabilityFilterComponent{}
}

// Settings populates a set of default valid resource types for the VulnerabilityFilterCriteria
// if none are provided via config.
func (v *VulnerabilityFilterComponent) Settings() *VulnerabilityFilterConfig {
	return &VulnerabilityFilterConfig{
		CVSSV2MinimumScore: 7.0,
		VulnIDRegexMatch:   ".*",
	}
}

// New constructs a VulnerabilityFilterCriteria from a config.
func (v *VulnerabilityFilterComponent) New(_ context.Context, c *VulnerabilityFilterConfig) (*VulnerabilityFilterCriteria, error) {
	return &VulnerabilityFilterCriteria{
		CVSSV2MinimumScore: c.CVSSV2MinimumScore,
		VulnIDRegexp:       regexp.MustCompile(c.VulnIDRegexMatch),
	}, nil
}

// VulnerabilityFilterCriteria filters Vulnerabilities based on various criteria
type VulnerabilityFilterCriteria struct {
	CVSSV2MinimumScore float64
	VulnIDRegexp       *regexp.Regexp
}
