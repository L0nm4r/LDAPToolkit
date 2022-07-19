package ldapPack

import (
	"LDAPToolkit/src/lib"
	"fmt"
	"testing"
)

func TestLdapAuthWithPass(t *testing.T) {
	conn, exception := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\hacker2",
		Token:    lib.Token{
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	defer conn.Close()
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}
}

func TestLdapAuthWithHash(t *testing.T) {
	// 失败可能是不支持NTLM认证LDAP
	// https://support.kaspersky.com/KWTS/6.1/zh-Hans/183656.htm
	conn, exception := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "administrator",
		// red\administrator 不行
		// administrator 行
		Token:    lib.Token{
			Token:     "3f7528021486bb6e9e10287b9341aa23",
			TokenType: "hash",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	defer conn.Close()
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}
}

func TestLdapSearch1(t *testing.T) {
	conn, exception := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "hacker2",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	defer conn.Close()
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}

	entries,exception := AttrSearch(conn, "CN=users,DC=red,DC=local", "ObjectSid=S-1-5-21-287611440-2308264118-3872617785-500", []string{})
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}
	for _,e := range entries {
		fmt.Println(e.DN)
		for _,a := range e.Attributes{
			fmt.Printf("%s : %s\n",a.Name,GetEntryAttributeValues(a))
		}
	}
}

func TestLdapSearch2(t *testing.T) {
	conn, exception := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "hacker2",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	defer conn.Close()
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}

	entries,exception := AttrSearch(conn, "DC=red,DC=local", "ObjectSid=S-1-5-21-287611440-2308264118-3872617785-1107", []string{"DN","ObjectSID"})
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}
	for _,e := range entries {
		fmt.Println(e.DN)
		for _,a := range e.Attributes{
			fmt.Printf("%s : %s\n",a.Name,GetEntryAttributeValues(a))
		}
	}
}

func TestLdapAdd(t *testing.T) {
	conn, exception := LDAPAuth(lib.LDAPInfo {
		Domain:   "red.local",
		Username: "red\\Administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	defer conn.Close()
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}
	b,exception := AttrAdd(conn,"CN=user1,CN=Users,DC=red,DC=local", "","description", []string{"hacked!123"})
	//b,exception := AttrAdd(conn,"CN=user1,CN=Users,DC=red,DC=local", "","description", []string{"hacked!123","abcdef"})
	// 添加失败, 原因: 这个属性只支持单个value
	if b && exception.IsNil(){
		fmt.Println("add success!")
	} else {
		fmt.Println(exception.Explain,exception.Err)
	}
}

func TestAttrClear(t *testing.T) {
	conn, exception := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\Administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	defer conn.Close()
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}
	b,exception := AttrClear(conn,"CN=user1,CN=Users,DC=red,DC=local", "","description")
	if b && exception.IsNil(){
		fmt.Println("Clear success!")
	} else {
		fmt.Println(exception.Explain,exception.Err)
	}
}

func TestAttrReplace(t *testing.T) {
	conn, exception := LDAPAuth(lib.LDAPInfo{
		Domain:   "red.local",
		Username: "red\\Administrator",
		Token:    lib.Token {
			Token:     "Abc@123!",
			TokenType: "password",
		},
		IP:       "192.168.6.100",
		Port:     "389",
	})
	defer conn.Close()
	if !exception.IsNil() {
		fmt.Println(exception.Err, exception.Explain)
	}
	b,exception := AttrReplace(conn,"CN=user1,CN=Users,DC=red,DC=local", "","description", []string{"changed!"})
	if b && exception.IsNil(){
		fmt.Println("Change success!")
	} else {
		fmt.Println(exception.Explain,exception.Err)
	}
}