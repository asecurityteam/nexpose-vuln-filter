package logs

const (
	// VulnRetained is an Action used to signify the vuln was retained
	VulnRetained = "retained"
	// VulnDiscarded is an Action used to signify the vuln was discarded
	VulnDiscarded = "discarded"
	// CvssV2Score signifies the method used to retain the vulnerability was the CVSS V2 Score
	CvssV2Score = "cvss_v2_score"
	// VulnID signifies the method used to retain the vulnerability was the vuln id
	VulnID = "vuln_id"
)

// VulnerabilityFiltered contains details on the filtering of an asset's vulnerabilities
type VulnerabilityFiltered struct {
	Action  string `logevent:"action"`
	Method  string `logevent:"method,default=n/a"`
	VulnID  string `logevent:"vuln_id"`
	AssetID int64  `logevent:"asset_id"`
}
