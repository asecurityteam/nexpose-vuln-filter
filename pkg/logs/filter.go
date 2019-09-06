package logs

const (
	// VulnAccepted is an Action used to signify the vuln was accepted.
	VulnAccepted = "accepted"
	// VulnDiscarded is an Action used to signify the vuln was discarded.
	VulnDiscarded = "discarded"
	// CvssV2Score signifies the method used to retain the vulnerability was the CVSS V2 Score.
	CvssV2Score = "cvss_v2_score"
	// VulnID signifies the method used to retain the vulnerability was the vuln id.
	VulnID = "vuln_id"
)

// VulnerabilityFiltered contains details on the filtering of an asset's vulnerabilities.
type VulnerabilityFiltered struct {
	Message string `logevent:"message,default=vulnerability-filtered"`
	Action  string `logevent:"action"`
	Method  string `logevent:"method,default=n/a"`
	VulnID  string `logevent:"vuln_id"`
	AssetID int64  `logevent:"asset_id"`
	Status  string `logevent:"status"`
}
