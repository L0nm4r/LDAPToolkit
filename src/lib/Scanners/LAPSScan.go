package Scanners

import (
	"LDAPToolkit/src/lib/ldapPack"
	"LDAPToolkit/src/lib/ldapPack/ACLPack/winacl"
	"LDAPToolkit/src/lib/logger"
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

func LAPSScan(conn *ldap.Conn, rootDN string) {
	// ms-Mcs-AdmPwd
	results,e := ldapPack.AttrSearch(conn, rootDN, UserFilter, []string{"ms-Mcs-AdmPwd"})
	if !e.IsNil() {
		logger.Error(e.String())
	}

	for _, r := range results {
		if len(r.Attributes) == 0 {
			continue
		}
		logger.Warn(fmt.Sprintf("ms-Mcs-AdmPwd pass found! %s / %s",r.DN, r.Attributes[0].Values))
	}
	// ms-Mcs-AdmPwd Guid is unique for each AD Forest.
	// schemaIDGUID : search CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=red,DC=local
	results,e = ldapPack.AttrSearch(conn,fmt.Sprintf("CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=red,DC=local"),"", []string{"schemaIDGUID"})
	if len(results) != 0 {
		if len(results[0].Attributes) != 0 {
			g := ldapPack.GUID{}
			g.FromBytes(results[0].Attributes[0].ByteValues[0])
			//fmt.Println(g.String())

			winacl.GuidMaps["ms-Mcs-AdmPwd"] = g.String()

			rule := ScanRule {
				ID:		0,
				DN:		"<rootDN>",
				Filter:	  "ObjectCategory=user",
				Type:     "ACCESS_ALLOWED_OBJECT",
				Restrict: true,
				Rights:   []string{"GenericWrite","GenericAll","WriteProperty"},
				GUIDStr: "ms-Mcs-AdmPwd",
				SIDRex:	  RuleRex {
					BlackList: "",
					WhiteList: "",
				},
				Description: "ms-Mcs-AdmPwd rights scan",
			}

			e := ACLScanner(conn,rootDN,rule)
			if !e.IsNil() {
				logger.Debug(e.String())
			}
		}
	}
}
