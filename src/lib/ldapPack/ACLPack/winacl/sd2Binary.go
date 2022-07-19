package winacl

import "bytes"

func RawSecurityDescriptor2Binary(sd NtSecurityDescriptor) ([]byte,error){
	var buff bytes.Buffer
	// Revision
	buff.WriteByte(sd.Header.Revision)
	// ControlFlags
	buff.WriteByte(0)
	buff.Write(MarshalInt16(sd.Header.Control))

	owner := SidToBytes(sd.Owner)
	group := SidToBytes(sd.Group)

	sacl, err := AclToBinary(sd.SACL)
	if err != nil {
		return nil, err
	}

	dacl,err := AclToBinary(sd.DACL)
	if err != nil {
		return nil, err
	}
	offset := 20
	// Owner SID
	if sd.Owner.Authority != nil && sd.Owner.SubAuthorities != nil{
		buff.Write(MarshalInt32(uint32(offset)))
		offset = offset + len(owner)
	} else {
		buff.Write(MarshalInt32(uint32(0)))
	}
	if sd.Group.Authority != nil && sd.Group.SubAuthorities != nil{
		buff.Write(MarshalInt32(uint32(offset)))
		offset = offset + len(group)
	} else {
		buff.Write(MarshalInt32(uint32(0)))
	}

	// SACL
	if len(sd.SACL.Aces) !=0 {
		buff.Write(MarshalInt32(uint32(offset)))
		offset = offset + len(sacl)
	}else {
		buff.Write(MarshalInt32(uint32(0)))
	}
	// DACL
	if len(sd.DACL.Aces) !=0 {
		buff.Write(MarshalInt32(uint32(offset)))
		offset = offset + len(dacl)
	}else {
		buff.Write(MarshalInt32(uint32(0)))
	}

	// data
	if sd.Owner.Authority != nil && sd.Owner.SubAuthorities != nil{
		buff.Write(owner)
	}
	if sd.Group.Authority != nil && sd.Group.SubAuthorities != nil{
		buff.Write(group)
	}
	if len(sd.SACL.Aces)!=0 {
		buff.Write(sacl)
	}
	if len(sd.DACL.Aces)!=0 {
		buff.Write(dacl)
	}
	return buff.Bytes(),nil
}

func MarshalInt16(number uint16) (bytes []byte){
	bytes = append(bytes, byte(number))
	bytes = append(bytes, byte(number >> 8))
	return bytes
}

func MarshalInt32(number uint32) (bytes []byte){
	bytes = append(bytes, byte(number))
	bytes = append(bytes, byte(number >> 8))
	bytes = append(bytes, byte(number >> 16))
	bytes = append(bytes, byte(number >> 24))
	return bytes
}