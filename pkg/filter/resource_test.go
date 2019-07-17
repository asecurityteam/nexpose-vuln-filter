package filter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVulnFilterConfigName(t *testing.T) {
	config := &VulnerabilityFilterConfig{}
	require.Equal(t, config.Name(), "vulnerabilityfilter")
}

func TestVulnFilterComponentDefaultConfig(t *testing.T) {
	component := &VulnerabilityFilterComponent{}
	config := component.Settings()
	require.Equal(t, config.CVSSV2MinimumScore, 7.0)
	require.Equal(t, config.VulnIDRegexMatch, ".*")
}
