package filter

import (
	"context"
	"regexp"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/logs"
)

// VulnerabilityFilterConfig defines the configuration options for a VulnerabilityFilter.
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
func (v *VulnerabilityFilterComponent) New(_ context.Context, c *VulnerabilityFilterConfig) (*VulnerabilityFilter, error) {
	return &VulnerabilityFilter{
		CVSSV2MinimumScore: c.CVSSV2MinimumScore,
		VulnIDRegexp:       regexp.MustCompile(c.VulnIDRegexMatch),
		LogFn:              domain.LoggerFromContext,
		StatFn:             domain.StatFromContext,
	}, nil
}

// VulnerabilityFilter implements the VulnerabilityFilter interface
type VulnerabilityFilter struct {
	CVSSV2MinimumScore float64
	VulnIDRegexp       *regexp.Regexp
	LogFn              domain.LogFn
	StatFn             domain.StatFn
}

// FilterVulnerabilities returns a filtered list of the filtered vulnerabilities
// based on pre-configured filter criteria.
func (f VulnerabilityFilter) FilterVulnerabilities(ctx context.Context, asset domain.Asset, vulnerabilities []domain.Vulnerability) []domain.Vulnerability {
	logger := f.LogFn(ctx)
	stater := f.StatFn(ctx)

	filteredVulnerabilities := make([]domain.Vulnerability, 0)
	for _, vuln := range vulnerabilities {
		if vuln.CvssV2Score > f.CVSSV2MinimumScore {
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnRetained,
				Method:  logs.CvssV2Score,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		} else if f.VulnIDRegexp.MatchString(vuln.ID) {
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnRetained,
				Method:  logs.VulnID,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		} else {
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnDiscarded,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
			})
			stater.Count("event.nexposevulnerability.filter.discarded", 1)
		}
	}
	return filteredVulnerabilities
}