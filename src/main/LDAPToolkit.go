package main

import (
	"LDAPToolkit/src/lib"
	"LDAPToolkit/src/lib/Scanners"
	"LDAPToolkit/src/lib/ldapPack"
	"LDAPToolkit/src/lib/logger"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"gopkg.in/alecthomas/kingpin.v2"
	"os"
	"strings"
)

var (
	app = kingpin.New("LDAPToolkit", "ldap tools.\texamples:" +
		"\n\tscan: LDAPToolkit --target-ip=192.168.6.100 --user=red\\administrator --token='Abc@123!' --token-type=password --domain=red.local scan")
	debug	= app.Flag("debug","enable debug mode.").Bool() // --debug

	ip	= app.Flag("target-ip", "target ip address").Required().String()
	port = app.Flag("target-port", "target port (default 389)").Default("389").Int()

	username = app.Flag("user", "domain user").Required().String()
	token = app.Flag("token", "ntlm hash or password").Required().String()
	tokenType = app.Flag("token-type", "token type \"hash\" or \"password\"").Required().String()

	domain = app.Flag("domain", "domain name").Required().String()

	scan	= app.Command("scan", "auto scan.")

	search  = app.Command("search", "search ldap entry.")
	searchDN = search.Arg("baseDN", "entey dn.").Required().String()
	searchFilter = search.Arg("filter","ldap filter").String()
	searchAttributes = search.Arg("attributes", "attributes").Strings()

	attrAdd  = app.Command("attrAdd", "add ldap entry attribute.")
	addDN = attrAdd.Arg("baseDN", "entey dn.").Required().String()
	addFilter = attrAdd.Arg("filter","ldap filter").Required().String()
	addAttr = attrAdd.Arg("attributeName", "add attribute").Required().String()
	addAttributes = attrAdd.Arg("attributes", "attributes").Required().Strings()

	attrReplace = app.Command("attrReplace", "replace ldap attribute")
	replaceDN = attrReplace.Arg("baseDN", "entey dn.").Required().String()
	replaceFilter = attrReplace.Arg("filter","ldap filter").Required().String()
	replaceAttr = attrReplace.Arg("attributeName", "add attribute").Required().String()
	replaceAttributes = attrReplace.Arg("attributes", "attributes").Required().Strings()

	attrClear = app.Command("attrClear", "clear ldap attribute value")
	clearedDN = attrClear.Arg("baseDN", "entey dn.").Required().String()
	clearedFilter = attrClear.Arg("filter","ldap filter").Required().String()
	clearedAttr = attrClear.Arg("attributeName", "add attribute").Required().String()

	entryDel = app.Command("entryDel", "del ldap entry.")
	deledDN = entryDel.Arg("dn", "entry dn, must be single").Required().String()

	addUser = app.Command("add-user","add machine or domain user.\n\tThe default SPN value is empty\n\tdefault pass is Abc@123!")
	userType = addUser.Arg("type", "'machine' or 'user'").Required().String()
	userName = addUser.Arg("username", "the name of added user").Required().String()

	changeUserPass = app.Command("passwd", "change user password.")
	passedUser = changeUserPass.Arg("username", "username").Required().String()
	newPass = changeUserPass.Arg("newpass", "new password").Required().String()

	 rightAdd = app.Command("right", "add right to user")
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	// acl scan / 委派探测
	case scan.FullCommand():
		conn,err := ConnectInit()
		if err != nil {
			fmt.Println(err)
			return
		}
		Scanners.Scan(conn,ConvertDomainToRootDN(*domain))
	// search
	case search.FullCommand():
		conn,err := ConnectInit()
		if err != nil {
			fmt.Println(err)
			return
		}
		if *searchFilter == "*" {
			*searchFilter = ""
		}

		entries,exception := ldapPack.AttrSearch(conn, *searchDN, *searchFilter, *searchAttributes)
		if !exception.IsNil() {
			fmt.Println(exception.Err, exception.Explain)
		}
		for _,e := range entries {
			fmt.Println(e.DN)
			for _,a := range e.Attributes{
				fmt.Printf("%s : %s\n",a.Name,ldapPack.GetEntryAttributeValues(a))
			}
		}
	case attrAdd.FullCommand():
		conn,err := ConnectInit()
		if err != nil {
			fmt.Println(err)
			return
		}
		b,exception := ldapPack.AttrAdd(conn,*addDN, *addFilter,*addAttr, *addAttributes)
		if b && exception.IsNil(){
			fmt.Println("add success!")
		} else {
			fmt.Println(exception.Explain,exception.Err)
		}
	case attrReplace.FullCommand():
		conn,err := ConnectInit()
		if err != nil {
			fmt.Println(err)
			return
		}
		b,exception := ldapPack.AttrReplace(conn,*replaceDN, *replaceFilter, *replaceAttr, *replaceAttributes)
		if b && exception.IsNil() {
			fmt.Println("Change success!")
		} else {
			fmt.Println(exception.Explain,exception.Err)
		}
	case attrClear.FullCommand():
		conn,err := ConnectInit()
		if err != nil {
			fmt.Println(err)
			return
		}
		b,exception := ldapPack.AttrClear(conn, *clearedDN, *clearedFilter,*clearedAttr)
		if b && exception.IsNil(){
			fmt.Println("Clear success!")
		} else {
			fmt.Println(exception.Explain,exception.Err)
		}
	case entryDel.FullCommand():
		conn,err := ConnectInit()
		if err != nil {
			fmt.Println(err)
			return
		}
		b, exc:= ldapPack.EntryDel(conn, *deledDN)
		if !exc.IsNil() || !b {
			fmt.Println(exc.String())
		} else {
			fmt.Println("del success")
		}
	case addUser.FullCommand():
		conn,err := ConnectInit()
		if err != nil {
			fmt.Println(err)
			return
		}

		attrs := []ldap.Attribute{}
		dn := ""
		if strings.EqualFold(*userType, "machine") {
			attrs = []ldap.Attribute{
				{Type: "objectClass", Vals: []string{"top", "organizationalPerson", "user", "person","computer"}},
				{"name", []string{*userName}},
				{"sAMAccountName", []string{fmt.Sprintf("%s$",*userName)}},
				{"userAccountControl", []string{fmt.Sprintf("%d", 0x0202)}},
				{"instanceType", []string{fmt.Sprintf("%d", 0x00000004)}},
				{"userPrincipalName", []string{fmt.Sprintf("%s@%s",*userName,*domain)}},
				{"accountExpires", []string{fmt.Sprintf("%d", 0x00000000)}},
			}
			dn = fmt.Sprintf("CN=%s,CN=Computers,%s",*userName,ConvertDomainToRootDN(*domain))
		} else {
			attrs = []ldap.Attribute {
				{Type: "objectClass", Vals: []string{"top", "organizationalPerson", "user", "person"}},
				{"name", []string{*userName}},
				{"sAMAccountName", []string{*userName}},
				{"userAccountControl", []string{fmt.Sprintf("%d", 0x0202)}},
				{"instanceType", []string{fmt.Sprintf("%d", 0x00000004)}},
				{"userPrincipalName", []string{fmt.Sprintf("%s@%s",*userName,domain)}},
				{"accountExpires", []string{fmt.Sprintf("%d", 0x00000000)}},
			}
			dn = fmt.Sprintf("CN=%s,CN=users,%s",*userName,ConvertDomainToRootDN(*domain))
		}

		b,ex:= ldapPack.EntryAdd(conn,dn,attrs)
		if ex.IsNil() && b {
			if err := ldapPack.AddUserPass(conn,dn,"Abc@123!"); err!=nil{
				fmt.Printf("[x] modify user %s pass error: %s",*userName,err)
				return
			}

			if err := ldapPack.EnableUser(conn,dn); err!=nil {
				fmt.Printf("[x] emable user %s error: %s",*userName,err)
				return
			}
			fmt.Println("add success")
		} else {
			fmt.Println("add entry error", ex.Err)
		}
	case changeUserPass.FullCommand():
		conn,err := ConnectInit()
		if err != nil {
			fmt.Println(err)
			return
		}
		err = ldapPack.AddUserPass(conn, fmt.Sprintf("CN=%s,CN=users,%s", *passedUser, ConvertDomainToRootDN(*domain)), *newPass)
		if err != nil {
			fmt.Println(err)
			return
		}
		logger.Info("change user pass success")
	}
}

func ConvertDomainToRootDN(domain string) (dn string) {
	dcs := strings.Split(domain,".")
	for i := 0; i < len(dcs); i++ {
		dn += "DC="+dcs[i] + ","
	}
	dn = strings.TrimSuffix(dn, ",")
	return dn
}

func ConnectInit() (*ldap.Conn,error) {
	if *debug {
		logger.DebugMode = true
	}
	authInfo := lib.LDAPInfo {
		Domain:   *domain,
		Username: *username,
		Token:    lib.Token {
			Token:     *token,
			TokenType: *tokenType,
		},
		IP:   *ip,
		Port: fmt.Sprintf("%d",*port),
	}
	conn, err := ldapPack.LDAPAuth(authInfo)
	if !err.IsNil() {
		fmt.Println(err.Explain)
		return nil,err.Err
	}
	return conn,nil
}