package ldapPack

import (
	"LDAPToolkit/src/lib"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"testing"
)

func TestAddComputer(t *testing.T) {
	conn, _ := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})


	name := "machine102"
	domain := "red.local"
	dn := "CN=machine101,CN=Computers,DC=red,DC=local"
	pass := "Abc@123!"

	attrs := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "organizationalPerson", "user", "person","computer"}},
		{"name", []string{name}},
		{"sAMAccountName", []string{fmt.Sprintf("%s$",name)}},
		{"userAccountControl", []string{fmt.Sprintf("%d", 0x0202)}},
		{"instanceType", []string{fmt.Sprintf("%d", 0x00000004)}},
		{"userPrincipalName", []string{fmt.Sprintf("%s@%s",name,domain)}},
		{"accountExpires", []string{fmt.Sprintf("%d", 0x00000000)}},
	}

	b,ex:=EntryAdd(conn,dn,attrs)
	if ex.IsNil() && b {
		if err := AddUserPass(conn,dn,pass); err!=nil{
			fmt.Printf("[x] modify user %s pass error: %s",name,err)
			return
		}

		if err := EnableUser(conn,dn); err!=nil{
			fmt.Printf("[x] emable user %s error: %s",name,err)
			return
		}
		fmt.Println("add success")
	} else {
		fmt.Println("add entry error", ex.Err)
	}
}

func TestDelComputer(t *testing.T) {
	conn, _ := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})

	b, exc:= EntryDel(conn, "CN=machine101,CN=Users,DC=red,DC=local")
	if !exc.IsNil() || !b {
		fmt.Println(exc.String())
	} else {
		fmt.Println("del success")
	}
}

func TestAddUser(t *testing.T) {
	conn, _ := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})


	name := "testuser1"
	domain := "red.local"
	dn := "CN=testuser1,CN=users,DC=red,DC=local"
	pass := "Abc@123!"

	attrs := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "organizationalPerson", "user", "person"}},
		{"name", []string{name}},
		{"sAMAccountName", []string{name}},
		{"userAccountControl", []string{fmt.Sprintf("%d", 0x0202)}},
		{"instanceType", []string{fmt.Sprintf("%d", 0x00000004)}},
		{"userPrincipalName", []string{fmt.Sprintf("%s@%s",name,domain)}},
		{"accountExpires", []string{fmt.Sprintf("%d", 0x00000000)}},
	}

	b,ex:=EntryAdd(conn,dn,attrs)
	if ex.IsNil() && b {
		if err := AddUserPass(conn,dn,pass); err!=nil{
			fmt.Printf("[x] modify user %s pass error: %s",name,err)
			return
		}

		if err := EnableUser(conn,dn); err!=nil{
			fmt.Printf("[x] emable user %s error: %s",name,err)
			return
		}

		fmt.Println("add success")
	} else {
		fmt.Println("add entry error", ex.Err)
	}
}

func TestAddUserToGroup(t *testing.T) {
	conn, _ := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})

	b,e := AttrAdd(conn,"CN=Domain Admins,CN=Users,DC=red,DC=local","objectCategory=Group","member",[]string{"CN=testuser1,CN=users,DC=red,DC=local"})
	if !b || !e.IsNil() {
		fmt.Println(e.String())
	} else {
		fmt.Println("add success")
	}
}

func TestClearComputerSPN(t *testing.T) {
	// servicePrincipalName
	conn, _ := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})

	b,e := AttrClear(conn,"CN=machine101,CN=Computers,DC=red,DC=local","","servicePrincipalName")
	if !b || !e.IsNil() {
		fmt.Println(e.String())
	} else {
		fmt.Println("clear success")
	}
}

func TestChangeComputerName(t *testing.T) {
	// sAMAccountName
	// servicePrincipalName
	conn, _ := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})

	b,e := AttrReplace(conn,"CN=machine101,CN=Computers,DC=red,DC=local","","sAMAccountName",[]string{"Abc123"})
	if !b || !e.IsNil() {
		fmt.Println(e.String())
	} else {
		fmt.Println("change success")
	}
}