package nexpose

import (
	"net"
)

// Asset represents a Nexpose asset response payload
// See: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getSiteAssets
type Asset struct {
	Addresses                  []Address          `json:"addresses"`
	AssessedForPolicies        bool               `json:"assessedForPolicies"`
	AssessedForVulnerabilities bool               `json:"assessedForVulnerabilities"`
	Configurations             []Configuration    `json:"configurations"`
	Databases                  []Database         `json:"databases"`
	Files                      []File             `json:"files"`
	History                    []HistoryEvent     `json:"history"`
	Hostname                   string             `json:"hostName"`
	Hostnames                  []HostnameSource   `json:"hostNames"`
	ID                         int64              `json:"id"`
	IDs                        []AssetIdentifier  `json:"ids"`
	IP                         net.IP             `json:"ip"`
	Links                      []Link             `json:"links"`
	MAC                        string             `json:"mac"`
	OS                         string             `json:"os"`
	OSFingerprint              OSFingerprint      `json:"osFingerprint"`
	RawRiskScore               float64            `json:"rawRiskScore"`
	RiskScore                  float64            `json:"riskScore"`
	Services                   []Service          `json:"services"`
	Software                   []Software         `json:"software"`
	Type                       string             `json:"type"`
	UserGroups                 []UserGroup        `json:"userGroups"`
	Users                      []User             `json:"users"`
	Vulnerabilties             VulnerabilityCount `json:"vulnerabilties"`
}

// Address represents the Address field of a Nexpose asset
type Address struct {
	IP net.IP `json:"ip"`
}

// Database represents associated databases
type Database struct {
	Description string `json:"description"`
	ID          int32  `json:"id"`
	Name        string `json:"name"`
}

// File represents a file found on an Asset
type File struct {
	Attributes []FileAttribute `json:"attributes"`
	Name       string          `json:"name"`
	Size       int64           `json:"size"`
	Type       string          `json:"type"`
}

// FileAttribute represents a name-value pair
type FileAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HistoryEvent represents a change to the asset
type HistoryEvent struct {
	Date                     string `json:"date"`
	Description              string `json:"description"`
	ScanID                   int64  `json:"scanID"`
	Type                     string `json:"type"`
	User                     string `json:"user"`
	Version                  int32  `json:"version"`
	VulnerabilityExceptionID int32  `json:"vulnerabilityExceptionID"`
}

// HostnameSource represents a hostname of an asset and where it is sourced
type HostnameSource struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// AssetIdentifier represents unique identifiers associated with an asset
type AssetIdentifier struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

// OSFingerprint represents operating system details
type OSFingerprint struct {
	Architecture   string          `json:"architecture"`
	Configurations []Configuration `json:"configuration"`
	CPE            CPE             `json:"cpe"`
	Description    string          `json:"description"`
	Family         string          `json:"family"`
	ID             int64           `json:"id"`
	Product        string          `json:"product"`
	SystemName     string          `json:"systemName"`
	Type           string          `json:"type"`
	Vendor         string          `json:"vendor"`
	Version        string          `json:"version"`
}

// CPE represents the Common Platform Enumeration (CPE) of the operating system
type CPE struct {
	Edition   string `json:"edition"`
	Language  string `json:"language"`
	Other     string `json:"other"`
	Part      string `json:"part"`
	Product   string `json:"product"`
	SWEdition string `json:"swEdition"`
	TargetHW  string `json:"targetHW"`
	TargetSW  string `json:"targetSW"`
	Update    string `json:"update"`
	Version22 string `json:"v2.2"`
	Version23 string `json:"v2.3"`
	Vendor    string `json:"vendor"`
	Version   string `json:"version"`
}

// Service represents a service on an Asset
type Service struct {
	Configurations  []Configuration  `json:"configurations"`
	Databases       []Database       `json:"databases"`
	Family          string           `json:"family"`
	Links           []Link           `json:"links"`
	Name            string           `json:"name"`
	Port            int32            `json:"port"`
	Product         string           `json:"product"`
	Protocol        string           `json:"protocol"`
	UserGroups      []UserGroup      `json:"userGroups"`
	Users           []User           `json:"users"`
	Vendor          string           `json:"vendor"`
	Version         string           `json:"version"`
	WebApplications []WebApplication `json:"webApplications"`
}

// UserGroup represents a group account associated with an Asset or Service
type UserGroup struct {
	ID   int32  `json:"id"`
	Name string `json:"name"`
}

// User represents a user associated with an Asset or Service
type User struct {
	FullName string `json:"fullName"`
	ID       int32  `json:"id"`
	Name     string `json:"name"`
}

// WebApplication represents a web application associated with a Service
type WebApplication struct {
	ID          int64     `json:"id"`
	Pages       []WebPage `json:"pages"`
	Root        string    `json:"root"`
	VirtualHost string    `json:"virtualHost"`
}

// WebPage represents a page found within a WebApplication
type WebPage struct {
	LinkType string `json:"linkType"`
	Path     string `json:"path"`
	Response int32  `json:"response"`
}

// Software represents the software discovered on an Asset
type Software struct {
	Configurations []Configuration `json:"configurations"`
	CPE            CPE             `json:"cpe"`
	Description    string          `json:"description"`
	Family         string          `json:"family"`
	ID             int64           `json:"id"`
	Product        string          `json:"product"`
	Type           string          `json:"type"`
	Vendor         string          `json:"vendor"`
	Version        string          `json:"version"`
}

// VulnerabilityCount is a tally of the types of vulnerabilities detected on an Asset
type VulnerabilityCount struct {
	Critical    int64 `json:"critical"`
	Exploits    int64 `json:"exploits"`
	MalwareKits int64 `json:"malwareKits"`
	Moderate    int64 `json:"moderate"`
	Severe      int64 `json:"severe"`
	Total       int64 `json:"total"`
}
