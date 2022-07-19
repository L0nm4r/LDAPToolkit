package Scanners

import (
	"LDAPToolkit/src/lib/ldapPack"
	"LDAPToolkit/src/lib/logger"
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

func getGroupMembers(conn *ldap.Conn,dn string) ([]string,error) {
	var members []string
	results, e := ldapPack.AttrSearch(conn,dn, SelfFilter(dn),[]string{"member","objectClass"})
	if !e.IsNil() {
		logger.Debug("%s not found", dn)
		return nil,fmt.Errorf("%s not found", dn)
	}
	if len(results) != 0 {
		if len(results[0].Attributes) == 2 {
			// group
			groupMembers := results[0].Attributes[1].Values
			for _, member := range groupMembers {
				if member == dn {
					continue
				}
				m,err := getGroupMembers(conn,member)
				if err != nil{
					logger.Debug("GetGroupMember Error: %s",err)
					continue
				}
				members = append(members, m...)
			}
		}else{
			members = append(members,dn)
		}
	}
	return members,nil
}

func GroupScan(conn *ldap.Conn, rootDN string) {
	groups, e := ldapPack.AttrSearch(conn, rootDN, GroupFilter, []string{"dn"})
	if !e.IsNil() {
		return
	}
	for _, group := range groups {
		members, err := getGroupMembers(conn,group.DN)
		if err != nil {
			continue
		}
		members = removeDuplicateElement(members)

		if len(members) == 1 && members[0] == group.DN {
			continue
		}
		scanResult := fmt.Sprintf("group: %s\n\t",group.DN)
		for _,m := range members {
			scanResult = scanResult + fmt.Sprintf("member: %s\n\t",m)
		}
		logger.Info(scanResult)
	}
}

func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}