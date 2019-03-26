package nexpose

// Configuration represents a name-value pair
type Configuration struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Link represents a hyperlink and relation
type Link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}
