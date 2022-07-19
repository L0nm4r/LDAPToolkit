package ldapPack

import (
	"LDAPToolkit/src/lib/Exception"
	"LDAPToolkit/src/lib/logger"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"strings"
)

func AttrSearch(conn *ldap.Conn, baseDN string, filter string, attributes []string) ([]*ldap.Entry, Exception.Exception){
	if filter == "" {
		filter = "(name=*)"
	} else if !strings.HasPrefix(filter,"(") {
		filter = fmt.Sprintf("(%s)",filter)
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)
	results, err := conn.Search(searchRequest)
	if err != nil {
		return nil, Exception.Exception{Err: err, Explain: fmt.Sprintf("search from %s error", baseDN)}
	}
	return results.Entries, Exception.Exception{}
}

// AttrReplace replace an existing attr, include clear an attr value
func AttrReplace(conn *ldap.Conn, baseDN string, filter string, attr string, newValues []string) (bool,Exception.Exception) {
	entries, exception:= AttrSearch(conn, baseDN, filter, []string{attr})
	if exception.IsNil() {
		if entries == nil {
			return false,Exception.Exception{Err: nil, Explain: "entries count is zero."}
		}
		for _, entry := range entries {
			if len(entry.Attributes) != 1 {
				logger.Warn("entry %s attr %s count is %d , can't be modified", entry.DN, attr, len(entry.Attributes))
				continue
			}
			logger.Info("modify %s", entry.DN)
			modifyReq := ldap.NewModifyRequest(entry.DN, nil)
			// handle ObjectSID and ObjectGUID
			modifyReq.Replace(entry.Attributes[0].Name, newValues)
			err := conn.Modify(modifyReq)
			if err != nil {
				logger.Debug("modify %s error, err: %s", entry.DN, err)
			}
		}
		logger.Info("after modified..")
		entries, exception = AttrSearch(conn, baseDN, filter, []string{attr})
		if exception.IsNil() {
			if entries == nil {
				return false,Exception.Exception{Err: nil, Explain: "twice get entries count is zero."}
			} else {
				for _, entry := range entries {
					if len(entry.Attributes) == 0 {
						logger.Warn("after modify entry %s attr %s count is %d", entry.DN, attr, len(entry.Attributes))
						continue
					} else {
						for i := 0; i < len(entry.Attributes); i++ {
							logger.Info("new %s attr %s", entry.DN, entry.Attributes[i].Values)
						}
					}
				}
			}
		} else {
			return false, exception
		}
		return true,Exception.Exception{}
	} else {
		return false, exception
	}
}

// AttrClear Clear attr values
func AttrClear(conn *ldap.Conn, baseDN string, filter string, attribute string) (bool,Exception.Exception) {
	b, exception := AttrReplace(conn, baseDN, filter, attribute, []string{})
	if !b {
		logger.Debug("clear %s error", attribute)
		return false, exception
	} else {
		logger.Info("clear success!")
		return true, Exception.Exception{}
	}
}

// AttrAdd add not set attr or add values.
func AttrAdd(conn *ldap.Conn,baseDN string, filter string, attr string, newValues []string) (bool,Exception.Exception) {
	entries, exception:= AttrSearch(conn, baseDN, filter, []string{attr})
	if exception.IsNil() {
		if entries == nil {
			return false,Exception.Exception{Err: nil, Explain: "entries count is zero."}
		}
		for _, entry := range entries {
			if len(entry.Attributes) != 1 {
				if len(entry.Attributes) == 0 {
					logger.Info("add %s to %s", attr, entry.DN)
					addReq := ldap.NewAddRequest(entry.DN, nil)
					// handle ObjectSID and ObjectGUID
					addReq.Attributes = append(addReq.Attributes, ldap.Attribute{
						Type: attr,
						Vals: newValues,
					})
					err := conn.Add(addReq)
					if err != nil {
						logger.Debug("add %s error, err: %s", entry.DN, err)
						// 虽然有时候会报错,但是可以添加成功
					}
				} else {
					logger.Warn("entry %s attr %s count is %d , can't be modified", entry.DN, attr, len(entry.Attributes))
					continue
				}
			}
			// len(entry.Attributes) == 1
			logger.Info("add %s to %s", attr, entry.DN)
			modifyReq := ldap.NewModifyRequest(entry.DN, nil)
			// handle ObjectSID and ObjectGUID
			modifyReq.Add(attr, newValues)
			err := conn.Modify(modifyReq)
			if err != nil {
				logger.Debug("add %s error, err: %s", entry.DN, err)
			}
		}
		logger.Info("after add..")
		entries, exception = AttrSearch(conn, baseDN, filter, []string{attr})
		if exception.IsNil() {
			if entries == nil {
				return false,Exception.Exception{Err: nil, Explain: "twice get entries count is zero."}
			} else {
				for _, entry := range entries {
					if len(entry.Attributes) == 0 {
						logger.Warn("after add entry %s attr %s count is %d", entry.DN, attr, len(entry.Attributes))
						continue
					} else {
						for i := 0; i < len(entry.Attributes); i++ {
							logger.Info("new %s attr %s", entry.DN, entry.Attributes[i].Values)
						}
					}
				}
			}
		} else {
			return false, exception
		}
		return true,Exception.Exception{}
	} else {
		return false, exception
	}
}