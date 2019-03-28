package filter

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVulnFiltererConfigName(t *testing.T) {
	config := &VulnerabilityFiltererConfig{}
	require.Equal(t, config.Name(), "VulnerabilityFilter")
}

func TestVulnFiltererComponentDefaultConfig(t *testing.T) {
	component := &VulnerabilityFiltererComponent{}
	config := component.Settings()
	require.Equal(t, config.CVSSV2MinimumScore, 7.0)
	require.Equal(t, config.VulnIDRegexMatch, ".*")
}
