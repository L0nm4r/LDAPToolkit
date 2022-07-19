package ldapPack

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

func SearchSID(conn *ldap.Conn,rootDN,sid string) string {
	res,e := AttrSearch(conn,rootDN, fmt.Sprintf("ObjectSid=%s",sid),[]string{"DN"})
	if !e.IsNil() {
		return ""
	}
	// 正常情况下只能有一个
	if len(res) == 1 {
		return res[0].DN
	}
	return ""
}
