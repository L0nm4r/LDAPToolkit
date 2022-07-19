package winacl

import (
	"bytes"
)

// Common ACE

func CommonAceToBinary(ace ACE) (buff []byte,err error) {
	header := ace.Header.ToBinary()
	buff = append(buff, header...)

	// access mask
	buff = append(buff, MarshalInt32(ace.AccessMask.Value)...)
	// Sid
	buff = append(buff, SidToBytes(ace.ObjectAce.GetPrincipal())...)
	return buff,nil
}

// Object ACE

func ObjectAceToBinary(ace ACE) ([]byte,error) {
	var buff []byte
	header := ace.Header.ToBinary()
	buff = append(buff, header...)

	// access mask
	buff = append(buff, MarshalInt32(ace.AccessMask.Value)...)

	// Object Flags
	buff = append(buff, MarshalInt32(uint32(ace.ObjectAce.GetInheritanceFlags()))...)

	// ObjectType GUID
	if ace.ObjectAce.GetObjectType() != "{00000000-0000-0000-0000-000000000000}" {
		rawdata := ace.ObjectAce.GetRawObjectType()
		guid, err := rawdata.ToBuffer()
		if err != nil {
			return nil, err
		}
		buff = append(buff, guid.Bytes()...)
	}

	// InheritedObjectAceType GUID
	if ace.ObjectAce.GetInheritedObjectType() != "{00000000-0000-0000-0000-000000000000}" {
		rawdata := ace.ObjectAce.GetRawInheritedObjectType()
		guid, err := rawdata.ToBuffer()
		if err != nil {
			return nil, err
		}
		buff = append(buff, guid.Bytes()...)
	}

	// Sid
	buff = append(buff, SidToBytes(ace.ObjectAce.GetPrincipal())...)
	return buff,nil
}

func (header *ACEHeader) ToBinary() ([]byte){
	var buff bytes.Buffer
	buff.WriteByte(byte(header.Type))
	buff.WriteByte(byte(header.Flags))
	buff.WriteByte(byte(header.Size))
	buff.WriteByte(byte(header.Size >> 8))
	return buff.Bytes()
}