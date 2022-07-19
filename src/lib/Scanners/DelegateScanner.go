package Scanners

import (
	"LDAPToolkit/src/lib/Exception"
	"LDAPToolkit/src/lib/ldapPack"
	"LDAPToolkit/src/lib/ldapPack/ACLPack/winacl"
	"LDAPToolkit/src/lib/logger"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"strconv"
	"strings"
)

// 委派扫描

func DelegateScan(conn *ldap.Conn, rootDN string) Exception.Exception {
	users, e := ldapPack.AttrSearch(conn, rootDN, UserFilter, []string{"dn"})
	if !e.IsNil() {
		return e
	}

	for _,user := range users {
		bingo,e := UnconstrainedDelegationScan(conn,user.DN)
		if bingo {
			logger.Warn(fmt.Sprintf("unconstrained delegation detected! DN: %s", user.DN))
		} else {
			if !e.IsNil() {
				logger.Debug(fmt.Sprintf("unconstrained delegation detect errorDN: %s", user.DN))
			}
		}

		spns,e := ConstrainedDelegationScan(conn,user.DN)
		if spns != nil {
			scanResult := fmt.Sprintf("dn: %s\n\t",user.DN)
			for _,s := range spns {
				scanResult = scanResult + fmt.Sprintf("spn: %s\n\t",s)
			}
			logger.Warn("constrainedDelegation detected! : " + scanResult)
		} else {
			if !e.IsNil() {
				logger.Debug(fmt.Sprintf("constrained delegation detect errorDN: %s", user.DN))
			}
		}

		sid, e := SourceBasedConstrainedDelegationScan(conn, user.DN)
		if !e.IsNil() {
			logger.Debug("error in SourceBasedConstrainedDelegationScan. dn = %s , err : %s",user.DN,e.Explain)
		}
		if sid != "" {
			name := ldapPack.SearchSID(conn,rootDN,sid)
			if name == "" {
				name = sid
			}
			logger.Warn(fmt.Sprintf("sourceBasedConstrainedDelegation detected: \tdn: %s\n\tuser: %s\n",user.DN,name))
		}

	}
	return Exception.Exception{}
}

func SelfFilter(dn string) string{
	return "(distinguishedName="+dn+")"
}

func UnconstrainedDelegationScan(conn *ldap.Conn,dn string) (bool,Exception.Exception) {
	results,e := ldapPack.AttrSearch(conn,dn, SelfFilter(dn),[]string{"userAccountControl"})
	if !e.IsNil() {
		return false,e
	}

	if len(results) != 0 {
		if len(results[0].Attributes)!=0 {
			uac,err := strconv.Atoi(results[0].Attributes[0].Values[0])
			if err != nil{
				return false,Exception.Exception{
					Err:     err,
					Explain: "convert uac error",
				}
			}
			if uac&524288 == 524288 {
				return true,Exception.Exception{}
			}
		}
	}
	return false, Exception.Exception{}
}

func ConstrainedDelegationScan(conn *ldap.Conn, dn string) ([]string, Exception.Exception) {
	results,e := ldapPack.AttrSearch(conn,dn, SelfFilter(dn),[]string{"msDS-AllowedToDelegateTo"})
	if !e.IsNil() {
		return nil,e
	}

	if len(results) != 0 {
		if len(results[0].Attributes)!=0 {
			spn := results[0].Attributes[0].Values
			return spn,Exception.Exception{}
		}
	}
	return nil,Exception.Exception{}
}

func SourceBasedConstrainedDelegationScan(conn *ldap.Conn, dn string)(string,Exception.Exception){
	results,e := ldapPack.AttrSearch(conn,dn, SelfFilter(dn),[]string{"msDS-AllowedToActOnBehalfOfOtherIdentity"})
	if !e.IsNil() {
		return "",e
	}

	if len(results) != 0 {
		if len(results[0].Attributes) !=0 {
			sd,err := winacl.NewRawSecurityDescriptor(results[0].Attributes[0].ByteValues[0],0)
			if err != nil {
				return "",Exception.Exception{Err: err, Explain: "init security descriptor error!"}
			}
			var sid string
			for i:=0;i<int(sd.DACL.Header.AceCount);i++{
				sid = sid + sd.DACL.Aces[i].ObjectAce.GetPrincipal().String()+ " |\\\n\t\t"
			}
			return strings.TrimSuffix(strings.TrimSpace(sid),"|\\"),Exception.Exception{}
		}
	}
	return "",Exception.Exception{}
}