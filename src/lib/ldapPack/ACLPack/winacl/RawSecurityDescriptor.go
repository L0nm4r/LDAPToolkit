package winacl

import (
	"bytes"
)

func NewRawSecurityDescriptor(ntsdBytes []byte,offset int) (NtSecurityDescriptor,error) {
	ntsd := NtSecurityDescriptor{}
	var err error
	// Owner
	num := UnmarshalInt(ntsdBytes,offset + 4)
	if num != 0 {
		ntsd.Owner, err = BytesToSid(ntsdBytes[offset+num:])
		if err != nil {
			return NtSecurityDescriptor{},err
		}
	}
	// Group
	num2 := UnmarshalInt(ntsdBytes,offset + 8)
	if num2 != 0 {
		ntsd.Group, err = BytesToSid(ntsdBytes[offset + num2:])
		if err != nil {
			return NtSecurityDescriptor{},err
		}
	}
	// SACL
	num3 := UnmarshalInt(ntsdBytes,offset + 12)
	if num3 != 0 {
		var saclBuf = bytes.NewBuffer(ntsdBytes[offset + num3:])
		ntsd.SACL,err = NewACL(saclBuf)
		if err != nil {
			return NtSecurityDescriptor{},err
		}
	}
	// DACL
	num4 := UnmarshalInt(ntsdBytes,offset + 16)
	if num4 != 0{
		var daclBuf = bytes.NewBuffer(ntsdBytes[offset + num4:])
		ntsd.DACL,err = NewACL(daclBuf)
		if err != nil {
			return NtSecurityDescriptor{},err
		}
	}
	ntsd.Header.OffsetOwner = uint32(num)
	ntsd.Header.OffsetGroup = uint32(num2)
	ntsd.Header.OffsetSacl = uint32(num3)
	ntsd.Header.OffsetDacl = uint32(num4)
	ntsd.Header.Control = uint16(int(ntsdBytes[offset+2]) + int(ntsdBytes[offset+3])<<8)
	ntsd.Header.Revision = ntsdBytes[offset+0]
	ntsd.Header.Sbz1 = ntsdBytes[offset+1]
	return ntsd, nil
}

func UnmarshalInt(binaryForm []byte, offset int) int{
	return int(binaryForm[offset]) +
		(int(binaryForm[offset + 1]) << 8) +
		(int(binaryForm[offset + 2]) << 16) +
		(int(binaryForm[offset + 3]) << 24)
}

func BytesToSid(val []byte) (SID,error){
	var sid SID
	sid.Revision = val[0]
	sid.NumAuthorities = val[1]
	sid.Authority = val[2:8]
	subAuthorities := val[8:]
	for i:=0 ; i< int(sid.NumAuthorities) ; i++ {
		sid.SubAuthorities = append(sid.SubAuthorities, btoi32(subAuthorities[0+4*i:4*(i+1)]))
	}
	return sid,nil
}

func SidToBytes(sid SID) ([]byte) {
	var buff bytes.Buffer
	buff.WriteByte(sid.Revision)
	buff.WriteByte(sid.NumAuthorities)
	buff.Write(sid.Authority)
	for _,subAuthority := range sid.SubAuthorities{
		buff.Write(MarshalInt32(subAuthority))
	}
	return buff.Bytes()
}

func btoi32(val []byte) uint32 {
	r := uint32(0)
	for i := uint32(0); i < 4; i++ {
		r |= uint32(val[i]) << (8 * i)
	}
	return r
}