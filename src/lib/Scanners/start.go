package Scanners

import (
	"github.com/go-ldap/ldap/v3"
)

func Scan(conn *ldap.Conn, rootDN string) {
	// ACL Scan
	for _,rule := range rules {
		// for debug:
		//if rule.ID != 29 {
		//	continue
		//}
		ACLScanner(conn,rootDN,rule)
	}

	// 委派扫描
	DelegateScan(conn,rootDN)
	LAPSScan(conn,rootDN)
	GroupScan(conn,rootDN)
}
