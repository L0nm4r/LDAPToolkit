package ldapPack

import (
	"LDAPToolkit/src/lib/Exception"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"golang.org/x/text/encoding/unicode"
	"log"
)

func EntryAdd(conn *ldap.Conn,dn string, newAttributes []ldap.Attribute) (bool,Exception.Exception) {
	// 判断是否存在
	e,exception := AttrSearch(conn,dn,"",[]string{})

	if !exception.IsNil() || e == nil {
		newAddReq := ldap.NewAddRequest(dn,nil)
		newAddReq.Attributes = newAttributes
		err := conn.Add(newAddReq)
		if err != nil {
			return false,Exception.Exception{
				Err:     err,
				Explain: "Add entry error",
			}
		}
		return true, Exception.Exception{}
	} else {
		return false, Exception.Exception{
			Err:     exception.Err,
			Explain: "entry already exists or search error",
		}
	}
}

func EntryDel(conn *ldap.Conn,dn string) (bool,Exception.Exception) {
	// 判断是否存在
	e,exception := AttrSearch(conn,dn,"",[]string{})
	if exception.IsNil() && len(e) != 0 {
		if len(e) != 1 {
			return false, Exception.Exception{
				Err:    nil,
				Explain: "more than one entry found!",
			}
		}
		delReq := ldap.NewDelRequest(dn,nil)
		err := conn.Del(delReq)
		if err != nil {
			return false, Exception.Exception{
				Err:     err,
				Explain: "del error",
			}
		}
		return true, Exception.Exception{}
	} else {
		return false, Exception.Exception{
			Err:     exception.Err,
			Explain: "entry not exists or search error",
		}
	}
}

// EntryModify Rename Or Move
func EntryModify(){
	// TODO:: lasted
}


func AddUserPass(conn *ldap.Conn, dn string,pass string) error {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("%q", pass))
	if err != nil {
		log.Fatal(err)
	}

	modReq := ldap.NewModifyRequest(dn, []ldap.Control{})
	modReq.Replace("unicodePwd", []string{pwdEncoded})

	err = conn.Modify(modReq)
	if err != nil {
		return err
	}
	return nil
}

func EnableUser(conn *ldap.Conn, dn string) error {
	modReq := ldap.NewModifyRequest(dn, []ldap.Control{})
	modReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", 0x0200)})
	if err := conn.Modify(modReq); err != nil {
		return err
	}
	return nil
}