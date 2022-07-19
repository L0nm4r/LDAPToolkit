package Scanners

const GroupFilter  string = "(objectCategory=group)"
const UserFilter   string = "(objectClass=user)"
const DomainFilter string = "(objectClass=domain)"
const ComputerFilter string = "(objectClass=computer)"
const EmptyFilter  string = "(name=*)"

var rules = []ScanRule{
	{
		ID:       1,
		DN:       "CN=Domain Admins,CN=Users,<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll", "GenericWrite", "WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid|AccountOperatorsSid)",
		},
		Description: "Domain Admins组的Generic权限(GenericAll|GenericWrite|WriteProperty)配置不当",
	},

	{
		ID:       2,
		DN:       "<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED_OBJECT",
		Restrict: true,
		Rights:   []string{"Self"},
		GUIDStr:  "Self-Membership",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "Exchange Windows Permissions",
		},
		Description: "AddMember权限控制不当",
	},

	{
		ID:       4,
		DN:       "CN=Enterprise Admins,CN=users,<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll", "GenericWrite", "WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid|AccountOperatorsSid)",
		},
		Description: "Enterprise Admins组的Generic权限(GenericAll|GenericWrite|WriteProperty)配置不当",
	},

	{
		ID:       5,
		DN:       "CN=Administrators,CN=Builtin,<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll", "GenericWrite", "WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid|AccountOperatorsSid)",
		},
		Description: "Administrators组的Generic权限(GenericAll|GenericWrite|WriteProperty)配置不当",
	},

	{
		ID:       6,
		DN:       "CN=Schema Admins,CN=users,<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll", "GenericWrite", "WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid|AccountOperatorsSid)",
		},
		Description: "SchemaAdmins组的Generic权限(GenericAll|GenericWrite|WriteProperty)配置不当",
	},

	{
		ID:       7,
		DN:       "CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll", "GenericWrite", "WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid|AccountOperatorsSid)",
		},
		Description: "ExchangeWindowsPermissions组的Generic权限(GenericAll|GenericWrite|WriteProperty)配置不当",
	},

	{
		ID:       8,
		DN:       "CN=Organization Management,OU=Microsoft Exchange Security Groups,<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll", "GenericWrite", "WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid)",
		},
		Description: "OrganizationManagement组的Generic权限(GenericAll|GenericWrite|WriteProperty)配置不当",
	},

	{
		ID:       9,
		DN:       "CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll", "GenericWrite", "WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid)",
		},
		Description: "ExchangeTrustedSubsystem组的Generic权限(GenericAll|GenericWrite|WriteProperty)配置不当",
	},

	{
		ID:       10,
		DN:       "<rootDN>",
		Filter:   GroupFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"WriteOwner"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|AccountOperatorsSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid)",
		},
		Description: "组的changing group owner权限配置不当",
	},

	//{
	//	ID:       11,
	//	DN:       "<rootDN>",
	//	Filter:   EmptyFilter,
	//	Type:     "ACCESS_ALLOWED",
	//	Restrict: true,
	//	Rights:   []string{"ExtendedRight"},
	//	GUIDStr:  "",
	//	SIDRex:	  RuleRex{
	//		BlackList: "",
	//		WhiteList: "(LocalSystemSid|\\-498$)",
	//	},
	//	Description: "异常的extended rights",
	//},

	{
		ID:       12,
		DN:       "CN=Administrator,CN=Users,<rootDN>",
		Filter:   EmptyFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll","GenericWrite","WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|AccountOperatorsSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid)",
		},
		Description: "Administrator的Generic权限配置不当",
	},

	{
		ID:       13,
		DN:       "CN=Users,<rootDN>",
		Filter:   UserFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|AccountOperatorsSid|DomainAdminsSid|EnterpriseAdminsSid|OrganizationManagementSid|AdministratorsSid)",
		},
		Description: "域用户GenericALL权限配置不当",
	},

	{
		ID:       14,
		DN:       "<rootDN>",
		Filter:   UserFilter,
		Type:     "ACCESS_ALLOWED_OBJECT",
		Restrict: true,
		Rights:   []string{},
		GUIDStr:  "User-Force-Change-Password",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid)",
		},
		Description: "域用户修改密码权限配置不当",
	},

	{
		ID:       16,
		DN:       "<rootDN>",
		Filter:   UserFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"WriteOwner"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|AccountOperatorsSid|EnterpriseAdminsSid|DomainAdminsSid|AdministratorsSid|SchemaAdminsSid)",
		},
		Description: "域用户WriteOwner权限配置不当",
	},

	{
		ID:		17,
		DN:		"CN=Policies,CN=System,<rootDN>",
		Filter:	  "(&(!(CN=User))(!(CN=Machine)))",
		Type:     "ACCESS_ALLOWED_OBJECT",
		Restrict: true,
		Rights:   []string{"WriteProperty","Synchronize"},
		GUIDStr: "GPC-File-Sys-Path",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid)",
		},
		Description: "组策略GPC-File-Sys-Path修改权限配置不当",
	},

	{
		ID:		18,
		DN:		"CN=Policies,CN=System,<rootDN>",
		Filter:	  "(&(!(CN=User))(!(CN=Machine)))",
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericWrite","GenericAll", "WriteProperty"},
		GUIDStr: "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(SelfSid|LocalSystemSid|EnterpriseAdminsSid|DomainAdminsSid|AdministratorsSid|SchemaAdminsSid|CreatorOwnerSid)",
		},
		Description: "组策略Generic权限配置不当",
	},


	{
		ID:		19,
		DN:		"CN=Policies,CN=System,<rootDN>",
		Filter:	  "(&(!cn=user)(!(cn=machine)))",
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"CreateChild"},
		GUIDStr: "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|EnterpriseAdminsSid|DomainAdminsSid|AdministratorsSid|SchemaAdminsSid|CreatorOwnerSid|GroupPolicyCreatorOwnersSid)",
		},
		Description: "组策略创建权限配置不当",
	},

	{
		ID:       20,
		DN:       "<rootDN>",
		Filter:   DomainFilter,
		Type:     "ACCESS_ALLOWED_OBJECT",
		Restrict: true,
		Rights:   []string{"ExtendedRight"},
		GUIDStr:  "DS-Replication-Get-Changes",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|EnterpriseDomainControllersSid|AdministratorsSid|DomainControllersSID|(\\-498))",
		},
		Description: "DCSync权限配置不当1-DS-Replication-Get-Changes",
	},

	{
		ID:       21,
		DN:       "<rootDN>",
		Filter:   DomainFilter,
		Type:     "ACCESS_ALLOWED_OBJECT",
		Restrict: true,
		Rights:   []string{"ExtendedRight"},
		GUIDStr:  "DS-Replication-Get-Changes-All",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|EnterpriseDomainControllersSid|AdministratorsSid|DomainControllersSID|(\\\\-498))",
		},
		Description: "DCSync权限配置不当2-DS-Replication-Get-Changes-All",
	},

	{
		ID:       22,
		DN:       "<rootDN>",
		Filter:   DomainFilter,
		Type:     "ACCESS_ALLOWED_OBJECT",
		Restrict: true,
		Rights:   []string{"ExtendedRight"},
		GUIDStr:  "DS-Replication-Get-Changes-In-Filtered-Set",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|EnterpriseDomainControllersSid|AdministratorsSid|DomainControllersSID|(\\\\-498))",
		},
		Description: "DCSync权限配置不当3-DS-Replication-Get-Changes-In-Filtered-Set",
	},

	{
		ID:       25,
		DN:       "<rootDN>",
		Filter:   DomainFilter,
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericAll","GenericWrite","WriteProperty"},
		GUIDStr:  "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(SelfSid|LocalSystemSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid)",
		},
		Description: "域对象Generic权限配置不当",
	},

	{
		ID:		26,
		DN:		"CN=adminSDHolder,CN=System,<rootDN>",
		Filter:	  "",
		Type:     "ACCESS_ALLOWED",
		Restrict: true,
		Rights:   []string{"GenericWrite","GenericAll","WriteProperty"},
		GUIDStr: "",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|DomainAdminsSid|EnterpriseAdminsSid|AdministratorsSid|AccountOperatorsSid)",
		},
		Description: "AdminSDHolder Generic 权限配置不当",
	},

	{
		ID:       28,
		DN:       "<rootDN>",
		Filter:   ComputerFilter,
		Type:     "ACCESS_ALLOWED_OBJECT",
		Restrict: true,
		Rights:   []string{"WriteProperty", "Synchronize"},
		GUIDStr:  "User-Account-Control",
		SIDRex:	  RuleRex{
			BlackList: "",
			WhiteList: "(LocalSystemSid|EnterpriseDomainControllersSid|AdministratorsSid|DomainControllersSID|Exchange Windows Permissions)",
		},
		Description: "攻击者可以通过修改机器账户UAC值将机器账户提升为'域控',之后利用机器账户进行DCSync.",
	},


	{
		ID:		29,
		DN:		"cn=dc2019,ou=domain controllers,<rootDN>",
		Filter:	  UserFilter,
		Type:     "ACCESS_ALLOWED_OBJECT",
		Restrict: true,
		Rights:   []string{"GenericWrite","GenericAll","WriteProperty","Synchronize"},
		// AccessMaskDelete
		GUIDStr: "ms-DS-Key-Credential-Link",
		SIDRex:	  RuleRex {
			BlackList: "",
			WhiteList: "(\\-527$|\\-526$)",
			//  Enterprise Key Admins group ( SID = <forest root domain SID>-527 )
			// -526: 不确定是否为固定格式,对于Key Admins来说.
			// 根据:https://github.com/MicrosoftDocs/windows-itpro-docs/issues/5243
			// 这两个组都默认对msDS-KeyCredentialLink有读写权限
		},
		Description: "ms-DS-Key-Credential-Link 写权限配置不当",
	},

	//{
	//	ID:		21,
	//	DN:		"<rootDN>",
	//	Filter:	  "",
	//	Type:     "",
	//	Restrict: true,
	//	Rights:   []string{""},
	//	GUIDStr: "",
	//	SIDRex:	  RuleRex {
	//		BlackList: "",
	//		WhiteList: "",
	//	},
	//	Description: "",
	//},

}

