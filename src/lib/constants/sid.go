package constants

var SidMap = map[string]string{
	"CreatorOwnerSid":                "S-1-3-0",
	"LocalAccountSid":                "S-1-5-113",
	"ServiceSid":                     "S-1-5-6",
	"AnonymousLogonSid":              "S-1-5-7",
	"EnterpriseDomainControllersSid": "S-1-5-9",
	"SelfSid":                        "S-1-5-10",
	"AuthenticatedUsersSid":          "S-1-5-11",
	"LocalSystemSid":                 "S-1-5-18",
	"AdministratorSid":               "S-1-5-\\d+-\\d+-\\d+-\\d+-500",
	"GuestSid":                       "S-1-5-\\d+-\\d+-\\d+-\\d+-501",
	"KrbtgtSid":                      "S-1-5-\\d+-\\d+-\\d+-\\d+-502",
	"DomainAdminsSid":                "S-1-5-\\d+-\\d+-\\d+-\\d+-512",
	"DomainUsersSid":                 "S-1-5-\\d+-\\d+-\\d+-\\d+-513",
	"DomainGuestsSid":                "S-1-5-\\d+-\\d+-\\d+-\\d+-514",
	"DomainComputersSid":             "S-1-5-\\d+-\\d+-\\d+-\\d+-515",
	"DomainControllersSID":           "S-1-5-\\d+-\\d+-\\d+-\\d+-516", // 区分 EnterpriseDomainControllersSid
	"CertPublishersSid":              "S-1-5-\\d+-\\d+-\\d+-\\d+-517",
	"SchemaAdminsSid":                "S-1-5-\\d+-\\d+-\\d+-\\d+-518",
	"EnterpriseAdminsSid":            "S-1-5-\\d+-\\d+-\\d+-\\d+-519",
	"GroupPolicyCreatorOwnersSid":    "S-1-5-\\d+-\\d+-\\d+-\\d+-520",
	"AdministratorsSid":              "S-1-5-32-544",
	"AccountOperatorsSid":            "S-1-5-32-548",
	"OrganizationManagementSid":	  "S-1-5-\\d+-\\d+-\\d+-\\d+-1104",
}