package constants


func SelfFilter(dn string) string{
	return "(distinguishedName="+dn+")"
}

const GroupFilter  string = "(objectCategory=group)"
const UserFilter   string = "(objectClass=user)"
const DomainFilter string = "(objectClass=domain)"
const ComputerFilter string = "(objectClass=computer)"
const EmptyFilter  string = "(name=*)"

// yaml规则parser中会用到的filter,与上面的const保持一致

var LdapFilter = map[string]string{
	"GroupFilter":  "(objectCategory=group)",
	"UserFilter":   "(objectClass=user)",
	"DomainFilter": "(objectClass=domain)",
	"EmptyFilter":  "(name=*)",
	"ComputerFilter": "(objectClass=computer)",
}

