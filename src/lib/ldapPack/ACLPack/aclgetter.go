package ACLPack

import (
	"LDAPToolkit/src/lib/Exception"
	"LDAPToolkit/src/lib/ldapPack"
	"LDAPToolkit/src/lib/ldapPack/ACLPack/winacl"
	"LDAPToolkit/src/lib/logger"
	"github.com/go-ldap/ldap/v3"
)

func GetSecurityDescriptor(conn *ldap.Conn, dn string, filter string) ([]winacl.NtSecurityDescriptor,Exception.Exception) {
	var res []winacl.NtSecurityDescriptor
	entries,e := ldapPack.AttrSearch(conn,dn,filter,[]string{"nTSecurityDescriptor"})
	if !e.IsNil() {
		return nil,e
	}
	//if len(entries) != 1 {
	//	return nil, Exception.Exception{Explain: "get entry not unique"}
	//}
	//entry := entries[0]
	for _,entry := range entries {
		if 	len(entry.Attributes) != 1 {
			return nil, Exception.Exception{Explain: "get attribute not unique"}
		}

		attr := entry.Attributes[0]
		for _,sdbytes := range attr.ByteValues {
			sd, err := winacl.NewRawSecurityDescriptor(sdbytes,0)
			if err != nil {
				logger.Debug("decode sd error, %s", err)
				continue
			}
			res = append(res, sd)
		}
	}
	return res,Exception.Exception{}
}

