package ldapPack

import (
	"LDAPToolkit/src/lib"
	"LDAPToolkit/src/lib/Exception"
	"LDAPToolkit/src/lib/logger"
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

func LDAPAuth(ldapInfo lib.LDAPInfo) (conn *ldap.Conn,exception Exception.Exception) {
	connect, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s",ldapInfo.IP, ldapInfo.Port))
	if err != nil {
		return &ldap.Conn{}, Exception.Exception{Err: err, Explain: "connect to remote server error"}
	}

	err = connect.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		logger.Debug("bind tls error.")
		connect, err = ldap.Dial("tcp", fmt.Sprintf("%s:%s",ldapInfo.IP, ldapInfo.Port))

		if err != nil {
			return &ldap.Conn{}, Exception.Exception{Err: err, Explain: "rebind remote server error"}
		}
	}

	switch ldapInfo.Token.TokenType {
		case "hash":
			err = connect.NTLMBindWithHash(ldapInfo.Domain, ldapInfo.Username, ldapInfo.Token.Token)
			// May fail because LDAPServer don't Support NTLM Auth https://support.kaspersky.com/KWTS/6.1/zh-Hans/183656.htm
			if err != nil {
				logger.Error("bind domain [%s] username [%s] with hash [%s] error", ldapInfo.Domain, ldapInfo.Username, ldapInfo.Token.Token)
				return &ldap.Conn{}, Exception.Exception{Err: err, Explain: fmt.Sprintf("bind domain [%s] username [%s] with hash [%s] error", ldapInfo.Domain, ldapInfo.Username, ldapInfo.Token.Token)}
			}
			break
		case "password":
			err = connect.Bind(ldapInfo.Username, ldapInfo.Token.Token)
			//err = connect.NTLMBind(ldapInfo.Username,ldapInfo.Username, ldapInfo.Token.Token)
			if err != nil {
				logger.Error("bind domain [%s] username [%s] with password [%s] error", ldapInfo.Domain, ldapInfo.Username, ldapInfo.Token.Token)
				return &ldap.Conn{}, Exception.Exception{Err: err, Explain: fmt.Sprintf("bind domain [%s] username [%s] with password [%s] error", ldapInfo.Domain, ldapInfo.Username, ldapInfo.Token.Token)}
			}
			break
	}
	logger.Info("bind to ldap server success")
	return connect,Exception.Exception{}
}