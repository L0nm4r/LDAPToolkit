package winacl

import "bytes"

func NtSecurityDescriptorToBinary(ntsd NtSecurityDescriptor) ([]byte,error){
	var buff bytes.Buffer
	// NTSDHeader
	buff.WriteByte(ntsd.Header.Revision)
	buff.WriteByte(ntsd.Header.Sbz1)
	buff.Write(MarshalInt16(ntsd.Header.Control))
	buff.Write(MarshalInt32(ntsd.Header.OffsetOwner))
	buff.Write(MarshalInt32(ntsd.Header.OffsetGroup))
	buff.Write(MarshalInt32(ntsd.Header.OffsetSacl))
	buff.Write(MarshalInt32(ntsd.Header.OffsetDacl))
	//ACL
	sacl, err := AclToBinary(ntsd.SACL)
	if err != nil {
		return nil, err
	}
	buff.Write(sacl)
	dacl, err := AclToBinary(ntsd.DACL)
	if err != nil {
		return nil, err
	}
	buff.Write(dacl)
	buff.Write(SidToBytes(ntsd.Owner))
	buff.Write(SidToBytes(ntsd.Group))
	return buff.Bytes(),nil
}