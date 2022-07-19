package Scanners

import (
	"LDAPToolkit/src/lib"
	"LDAPToolkit/src/lib/ldapPack"
	"testing"
)

func TestGenericRightScanner(t *testing.T) {
	conn, _ := ldapPack.LDAPAuth(lib.LDAPInfo {
		Domain:   "red.local",
		Username: "red\\administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	for _,rule := range rules {
		ACLScanner(conn,"DC=red,DC=local",rule)
	}
}