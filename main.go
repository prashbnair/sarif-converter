package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type AnalysedDependencies struct {
	Name                         string
	Version                      string
	Transitives                  []AnalysedDependencies
	LatestVersion                string
	RecommendedVersion           string
	CommonlyKnownVulnerabilities []Vulnerability
	VulnerabilitiesUniqueToSnyk  []Vulnerability
	VulerableTransitives         []AnalysedDependencies
}

type Vulnerability struct {
	CveIds   []string
	Cvss     float32
	Id       string
	Severity string
	Title    string
	URL      string
	Kind     string
}

type SeverityType struct {
	Low      []Vulnerability
	Medium   []Vulnerability
	High     []Vulnerability
	Critical []Vulnerability
}

type StackResponse struct {
	Deps                     []AnalysedDependencies
	TotalDirectDependencies  int
	TotalScannedDependencies int
	TransitiveVulnerabilites int
	Severity                 SeverityType
}

func main(args ...string) {
	content, err := os.ReadFile("/Users/pnair/cra/SpaceX-API/output.json")

	if err != nil {
		fmt.Println(err)
	}

	var analysedDependencies AnalysedDependencies
	json.Unmarshal(content, &analysedDependencies)
}
