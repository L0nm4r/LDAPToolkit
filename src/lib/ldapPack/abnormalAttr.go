package ldapPack

import (
	"LDAPToolkit/src/lib/ldapPack/ACLPack/winacl"
	"LDAPToolkit/src/lib/logger"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"strings"
)

func beautify(sddl string) string {

	sddl = strings.Replace(sddl, "O:", "\nO:", 1)
	sddl = strings.Replace(sddl, "(", "\n(", 1)
	for k,v := range winacl.GUIDS {
		sddl = strings.ReplaceAll(sddl, k, v)
	}
	return sddl
}

func dumpSD(attr *ldap.EntryAttribute) []string {
	var result []string
	if len(attr.ByteValues) > 0 {
		for _,byteValues := range attr.ByteValues {
			descriptors, err := winacl.NewRawSecurityDescriptor(byteValues, 0)
			if err != nil {
				logger.Debug(fmt.Sprintf("%s",err))
				continue
			}
			result = append(result, beautify(descriptors.ToSDDL()))
		}
	}
	return result
}

func GetEntryAttributeValues(attr *ldap.EntryAttribute) []string {
	switch strings.ToLower(attr.Name) {
	case "ntsecuritydescriptor":
		return dumpSD(attr)
	case "objectguid","schemaidguid",
	strings.ToLower("msDFSR-ContentSetGuid"), strings.ToLower("msDFSR-ReplicationGroupGuid"):
		var res []string
		for i := 0; i < len(attr.ByteValues); i++ {
			g := GUID{}
			g.FromBytes(attr.ByteValues[i])
			res = append(res, g.String())
		}
		return res
	case "objectsid", strings.ToLower("mS-DS-CreatorSID"):
		var res []string
		for i := 0; i < len(attr.ByteValues); i++ {
			g := SID{}
			g.FromBytes(attr.ByteValues[i])
			res = append(res, g.String())
		}
		return res
	// 这几个属性Windows自己的ADSI编辑器都不正常显示
	case "usercertificate":
		var res []string
		for i := 0; i < len(attr.ByteValues); i++ {
			res = append(res, fmt.Sprintf("%#x", attr.ByteValues[i]))
		}
		return res
	case "logonhours":
		var res []string
		for i := 0; i < len(attr.ByteValues); i++ {
			res = append(res, fmt.Sprintf("%#x", attr.ByteValues[i]))
		}
		return res
	default:
		return attr.Values
	}
}