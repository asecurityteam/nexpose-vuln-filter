package filter

import (
	"context"
	"regexp"
)

// VulnerabilityFiltererConfig defines the configuration options for a VulnerabilityFilterer.
type VulnerabilityFiltererConfig struct {
	CVSSV2MinimumScore float64 `description:"The minimum CVSS V2 score threshold for vulnerabilties to further process."`
	VulnIDRegexMatch   string  `description:"A regex to match the vulnerability ID to include for further processing."`
}

// Name is used by the settings library to replace the default naming convention.
func (v *VulnerabilityFiltererConfig) Name() string {
	return "VulnerabilityFilter"
}

// VulnerabilityFiltererComponent satisfies the settings library Component API,
// and may be used by the settings.NewComponent function.
type VulnerabilityFiltererComponent struct{}

// Settings populates a set of default valid resource types for the VulnerabilityFilterer
// if none are provided via config.
func (v *VulnerabilityFiltererComponent) Settings() *VulnerabilityFiltererConfig {
	return &VulnerabilityFiltererConfig{
		CVSSV2MinimumScore: 7.0,
		VulnIDRegexMatch:   ".*",
	}
}

// New constructs a VulnerabilityFilterer from a config.
func (v *VulnerabilityFiltererComponent) New(_ context.Context, c *VulnerabilityFiltererConfig) (*VulnerabilityFilterer, error) {
	return &VulnerabilityFilterer{
		CVSSV2MinimumScore: c.CVSSV2MinimumScore,
		VulnIDRegexp:       regexp.MustCompile(c.VulnIDRegexMatch),
	}, nil
}

// VulnerabilityFilterer filters Vulnerabilities based on various criteria
type VulnerabilityFilterer struct {
	CVSSV2MinimumScore float64
	VulnIDRegexp       *regexp.Regexp
}
