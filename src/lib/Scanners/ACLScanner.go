package Scanners

import (
	"LDAPToolkit/src/lib/Exception"
	"LDAPToolkit/src/lib/ldapPack"
	"LDAPToolkit/src/lib/ldapPack/ACLPack"
	"LDAPToolkit/src/lib/ldapPack/ACLPack/winacl"
	"LDAPToolkit/src/lib/logger"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"regexp"
	"strings"
)

func ACLScanner(conn *ldap.Conn, rootDN string, rule ScanRule) Exception.Exception {
	var filter string

	dn := ConvertDN(rule.DN,rootDN)
	filter = rule.Filter

	if filter == "" {
		filter = "(name=*)"
	} else if !strings.HasPrefix(filter,"(") {
		filter = fmt.Sprintf("(%s)",filter)
	}

	sds, e := ACLPack.AclSearch(conn, dn, filter)
	if !e.IsNil() {
		logger.Debug(e.String())
		return e
	}

	blacklist := ConvertSid(rule.SIDRex.BlackList)
	whitelist := ConvertSid(rule.SIDRex.WhiteList)
	rights := ConvertRight(rule.Rights)
	for _,sd := range sds {
		for _,ace := range sd.DACL.Aces {
			if winacl.ACETypeLookup[ace.GetType()] != rule.Type {
				//skip := true
				//DangerousRights := []string{"GenericWrite","WriteDacl","WriteProperty","GenericAll"}
				//for _,rname := range DangerousRights {
				//	if CheckRights(ace.AccessMask.Value,constants.AdRights[rname]){
				//		skip = false
				//		break
				//	}
				//}
				//if skip {
				//	continue
				//}
				continue
			}

			if blacklist != "" {
				bingo,err := regexp.MatchString(blacklist,ace.ObjectAce.GetPrincipal().String())
				if err != nil {
					logger.Error("%s",err)
					continue
				}

				if bingo {
					// 黑名单 bingo
					CheckRule(conn, rootDN, rule, rights, ace)
				}
			}

			if whitelist != "" {
				bingo,err := regexp.MatchString(whitelist,ace.ObjectAce.GetPrincipal().String())
				if err != nil {
					logger.Debug("%s",err)
					continue
				}
				if bingo {
					continue
				}
				CheckRule(conn, rootDN, rule, rights, ace)
			} else {
				CheckRule(conn, rootDN, rule, rights, ace)
			}
		}
	}
	return Exception.Exception{}
}

func CheckRule (conn *ldap.Conn, rootDN string, rule ScanRule, rights [][]uint8, ace winacl.ACE) {
	// any right!
	if len(rights) == 0 {
		CheckObject(conn,rootDN,rule,ace)
		return
	}
	// 黑名单 bingo
	if rule.Restrict {
		for _,right := range rights {
			if !CheckRights(ace.AccessMask.Value, right) {
				continue
			}

			if CheckObject(conn,rootDN,rule,ace) {
				break
			}
		}
		return
	}

	if !CheckMergedRights(ace.AccessMask.Value,rights) {
		return
	}

	CheckObject(conn,rootDN,rule,ace)
}

func CheckGUID(rule ScanRule, ace winacl.ACE) bool {
	//rule.GUIDStr
	guid := winacl.GuidMaps[rule.GUIDStr]
	match1, _ := regexp.MatchString("(?i)"+guid,ace.ObjectAce.GetObjectType())
	match2, _ := regexp.MatchString("(?i)"+guid,ace.ObjectAce.GetInheritedObjectType())

	if match1 || match2 {
		return true
	}
	return false
}

func CheckObject(conn *ldap.Conn, rootDN string, rule ScanRule, ace winacl.ACE) bool {
	g := false
	if rule.GUIDStr != "" && (rule.Type == "ACCESS_ALLOWED_OBJECT" || rule.Type == "ACCESS_DENIED_OBJECT" ) {
		if !CheckGUID(rule,ace) {
			return false
		}
		g = true
	}

	sid := ldapPack.SearchSID(conn,rootDN,ace.ObjectAce.GetPrincipal().String())
	if sid != "" {
		if g {
			logger.Warn(fmt.Sprintf("%s: %s | attr:%s:%s\n%s",rule.Description, sid,rule.GUIDStr,winacl.GuidMaps[rule.GUIDStr], ace))
			return true
		}
		logger.Warn(fmt.Sprintf("%s: %s\n%s",rule.Description, sid, ace))
	} else {
		if g {
			logger.Warn(fmt.Sprintf("%s: %s | attr:%s:%s\n%s",rule.Description, sid,rule.GUIDStr,winacl.GuidMaps[rule.GUIDStr], ace))
			return true
		}
		logger.Warn(fmt.Sprintf("%s: %s\n%s",rule.Description, ace.ObjectAce.GetPrincipal().Resolve(), ace))
	}
	return true
}