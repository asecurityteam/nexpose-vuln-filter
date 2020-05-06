package filter

import (
	"context"
	"fmt"
	"regexp"

	"github.com/asecurityteam/nexpose-vuln-filter/pkg/domain"
	"github.com/asecurityteam/nexpose-vuln-filter/pkg/logs"
)

const (
	invulnerable string = "invulnerable"
	noResults    string = "no-results"
	unknown      string = "unknown"
)

// VulnerabilityFilterConfig defines the configuration options for a VulnerabilityFilter.
type VulnerabilityFilterConfig struct {
	CVSSV2MinimumScore  float64 `description:"The minimum CVSS V2 score threshold for vulnerabilties to further process."`
	VulnIDRegexMatch    string  `description:"A regex to match the vulnerability ID to include for further processing."`
	AllowAllLocalChecks bool    `description:"A boolean of whether to allow all local, authenticated checks to pass through the filter, regardless of CVSS V2 score."`
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
		CVSSV2MinimumScore:  7.0,
		VulnIDRegexMatch:    ".*",
		AllowAllLocalChecks: true,
	}
}

// New constructs a VulnerabilityFilterCriteria from a config.
func (v *VulnerabilityFilterComponent) New(_ context.Context, c *VulnerabilityFilterConfig) (*VulnerabilityFilter, error) {
	expression, err := regexp.Compile(c.VulnIDRegexMatch)
	if err != nil {
		return &VulnerabilityFilter{}, err
	}

	return &VulnerabilityFilter{
		CVSSV2MinimumScore:  c.CVSSV2MinimumScore,
		VulnIDRegexp:        expression,
		AllowAllLocalChecks: c.AllowAllLocalChecks,
		LogFn:               domain.LoggerFromContext,
		StatFn:              domain.StatFromContext,
	}, nil
}

// VulnerabilityFilter implements the VulnerabilityFilter interface.
type VulnerabilityFilter struct {
	CVSSV2MinimumScore  float64
	VulnIDRegexp        *regexp.Regexp
	AllowAllLocalChecks bool
	LogFn               domain.LogFn
	StatFn              domain.StatFn
}

// FilterVulnerabilities returns a filtered list of the filtered vulnerabilities
// based on pre-configured filter criteria.
func (f VulnerabilityFilter) FilterVulnerabilities(ctx context.Context, asset domain.Asset, vulnerabilities []domain.Vulnerability) []domain.Vulnerability {
	logger := f.LogFn(ctx)
	stater := f.StatFn(ctx)

	filteredVulnerabilities := make([]domain.Vulnerability, 0)
	for _, vuln := range vulnerabilities {
		switch {
		case vuln.Status == invulnerable:
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnDiscarded,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
				Status:  vuln.Status,
			})
			stater.Count("event.nexposevulnerability.filter.discarded", 1, fmt.Sprintf("reason:%s", invulnerable))
		case vuln.Status == noResults:
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnDiscarded,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
				Status:  vuln.Status,
			})
			stater.Count("event.nexposevulnerability.filter.discarded", 1, fmt.Sprintf("reason:%s", noResults))
		case f.AllowAllLocalChecks == true && vuln.LocalCheck == true:
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnDiscarded,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
				Status:  vuln.Status,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		case vuln.CvssV2Score > f.CVSSV2MinimumScore:
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnAccepted,
				Method:  logs.CvssV2Score,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
				Status:  vuln.Status,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		case f.VulnIDRegexp.MatchString(vuln.ID):
			filteredVulnerabilities = append(filteredVulnerabilities, vuln)
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnAccepted,
				Method:  logs.VulnID,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
				Status:  vuln.Status,
			})
			stater.Count("event.nexposevulnerability.filter.accepted", 1)
		default:
			logger.Info(logs.VulnerabilityFiltered{
				Action:  logs.VulnDiscarded,
				VulnID:  vuln.ID,
				AssetID: asset.ID,
				Status:  vuln.Status,
			})
			stater.Count("event.nexposevulnerability.filter.discarded", 1, fmt.Sprintf("reason:%s", unknown))
		}
	}
	return filteredVulnerabilities
}
