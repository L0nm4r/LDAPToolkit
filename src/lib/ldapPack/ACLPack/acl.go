package ACLPack

import (
	"LDAPToolkit/src/lib/Exception"
	"LDAPToolkit/src/lib/ldapPack/ACLPack/winacl"
	"LDAPToolkit/src/lib/logger"
	"github.com/go-ldap/ldap/v3"
)

func AclSearch(conn *ldap.Conn, dn string, filter string) ([]winacl.NtSecurityDescriptor,Exception.Exception){
	//entries,e := ldapPack.AttrSearch(conn, dn, "", []string{"DN"})
	//if !e.IsNil() || entries == nil {
	//	return nil,Exception.Exception{
	//		Err:     e.Err,
	//		Explain: fmt.Sprintf("search dn %s error", dn),
	//	}
	//}
	//
	//var sds []winacl.NtSecurityDescriptor
	//for _,entry := range entries {
	//	tmp_sds,e := GetSecurityDescriptor(conn, entry.DN)
	//	if !e.IsNil() {
	//		logger.Error(e.String())
	//		return nil, e
	//	}
	//	sds = append(sds, tmp_sds...)
	//}
	sds,e := GetSecurityDescriptor(conn, dn, filter)
	if !e.IsNil() {
		logger.Debug(e.String())
		return nil, e
	}
	return sds,Exception.Exception{}
}