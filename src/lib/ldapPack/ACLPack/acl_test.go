package ACLPack

import (
	"LDAPToolkit/src/lib"
	"LDAPToolkit/src/lib/ldapPack"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestGetSecurityDescriptor(t *testing.T) {
	conn, _ := ldapPack.LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	sds,e := GetSecurityDescriptor(conn, "CN=administrator,CN=users,DC=red,DC=local","")
	if !e.IsNil() {
		panic(e.String())
	}

	//fmt.Println(sds[0].Owner)
	//fmt.Println(sds[0].Group)
	// SD应该只有一个?
	fmt.Printf("DACL counts: %d\tSCAL counts:%d\n",sds[0].DACL.Header.AceCount,sds[0].SACL.Header.AceCount)
	fmt.Println("filtered results: ")
	fmt.Println("DACL: ")
	for _,ace := range sds[0].DACL.Aces{
		if len(strings.Split(ace.ObjectAce.GetPrincipal().String(),"-")) <= 5 {
			continue
		}
		fmt.Println(ace)
	}
	fmt.Println("SACL: ")
	for _,ace := range sds[0].SACL.Aces{
		if len(strings.Split(ace.ObjectAce.GetPrincipal().String(),"-")) <= 5 {
			continue
		}
		fmt.Println(ace)
	}
}

func contains(s []string, searchterm string) bool {
	i := sort.SearchStrings(s, searchterm)
	return i < len(s) && s[i] == searchterm
}