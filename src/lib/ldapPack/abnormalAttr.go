package ldapPack

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

func GetEntryAttributeValues(attr *ldap.EntryAttribute) []string {
	switch attr.Name {
	case "objectGUID","schemaIDGUID":
		var res []string
		for i := 0; i < len(attr.ByteValues); i++ {
			g := GUID{}
			g.FromBytes(attr.ByteValues[i])
			res = append(res, g.String())
		}
		return res
	case "objectSid":
		var res []string
		for i := 0; i < len(attr.ByteValues); i++ {
			g := SID{}
			g.FromBytes(attr.ByteValues[i])
			res = append(res, g.String())
		}
		return res
	// 这几个属性Windows自己的ADSI编辑器都不正常显示
	case "userCertificate":
		var res []string
		for i := 0; i < len(attr.ByteValues); i++ {
			res = append(res, fmt.Sprintf("%#x", attr.ByteValues[i]))
		}
		return res
	case "logonHours":
		var res []string
		for i := 0; i < len(attr.ByteValues); i++ {
			res = append(res, fmt.Sprintf("%#x", attr.ByteValues[i]))
		}
		return res
	default:
		return attr.Values
	}
}