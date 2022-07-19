package Scanners

type RuleRex struct {
	WhiteList string
	BlackList string
}

type GUIDRight struct {
	Guid string
	Rights string
}

type ScanRule struct {
	ID 			int
	DN          string
	Filter		string
	Type        string
	Restrict    bool // 严格匹配,开启,则存在任意一个Right上报,否则匹配所有Right上报
	Rights      []string
	GUIDStr     string // attr guid
	SIDRex      RuleRex
	Description string
}
