package winacl

import "fmt"

// func (header *ACLHeader) ToBuffer() (bytes.Buffer, error)

func AclToBinary(acl ACL) (buff []byte,err error){
	header, _ := acl.Header.ToBuffer()
	buff = append(buff, header.Bytes()...)
	var rawAce []byte
	for _,ace := range acl.Aces {
		switch ace.Header.Type {
		case AceTypeAccessAllowed, AceTypeAccessDenied, AceTypeSystemAudit, AceTypeSystemAlarm, AceTypeAccessAllowedCallback, AceTypeAccessDeniedCallback, AceTypeSystemAuditCallback, AceTypeSystemAlarmCallback:
			rawAce,err = CommonAceToBinary(ace)
			if err !=nil {
				fmt.Printf("[x] CommonAceToBinary error : %s\n",err)
				continue
			}
			break
		case AceTypeAccessAllowedObject, AceTypeAccessDeniedObject, AceTypeSystemAuditObject, AceTypeSystemAlarmObject, AceTypeAccessAllowedCallbackObject, AceTypeAccessDeniedCallbackObject, AceTypeSystemAuditCallbackObject, AceTypeSystemAlarmCallbackObject:
			rawAce,err = ObjectAceToBinary(ace)
			if err !=nil {
				fmt.Printf("[x] CommonAceToBinary error : %s\n",err)
				continue
			}
			break
		}
		buff = append(buff, rawAce...)
	}

	return buff,nil
}