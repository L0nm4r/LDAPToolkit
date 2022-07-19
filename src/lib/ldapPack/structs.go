package ldapPack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

type SID struct {
	Revision       byte
	NumAuthorities byte
	Authority      []byte
	SubAuthorities []uint32
}

func (sid *SID) String() string {
	var sb strings.Builder

	if len(sid.Authority) < 6 {
		return ""
	}

	fmt.Fprintf(&sb, "S-%v-%v", sid.Revision, int(sid.Authority[5]))
	for i := 0; i < int(sid.NumAuthorities); i++ {
		fmt.Fprintf(&sb, "-%v", sid.SubAuthorities[i])
	}

	return sb.String()
}

func (sid *SID) FromBytes(data []byte) {
	if revision := data[0]; revision != 1 {
		return
	} else if numAuth := data[1]; numAuth > 15 {
		return
	} else if ((int(numAuth) * 4) + 8) < len(data) {
		return
	} else {
		authority := data[2:8]
		subAuth := make([]uint32, numAuth)
		for i := 0; i < int(numAuth); i++ {
			offset := 8 + (i * 4)
			subAuth[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
		}

		sid.Revision = revision
		sid.Authority = authority
		sid.NumAuthorities = numAuth
		sid.SubAuthorities = subAuth

		return
	}
}

func (sid *SID) ToBytes() []byte {
	var buff bytes.Buffer
	buff.WriteByte(sid.Revision)
	buff.WriteByte(sid.NumAuthorities)
	buff.Write(sid.Authority)
	for _,subAuthority := range sid.SubAuthorities{
		buff.Write(MarshalInt32(subAuthority))
	}
	return buff.Bytes()
}

func (sid *SID) FromString(s string) {
	subs := strings.Split(s,"-")
	r1,err  := strconv.ParseUint(subs[1], 16, 8)
	if err != nil {
		return
	}
	sid.Revision = uint8(r1)

	r2,err := strconv.ParseUint(subs[1], 16, 8)
	if err != nil {
		return
	}

	sa5 := uint8(r2)
	sid.Authority = []byte{0,0,0,0,sa5,0}

	sid.NumAuthorities = byte(len(subs) - 3)
	for i := 0; i < int(sid.NumAuthorities); i++ {
		g, err := strconv.ParseUint(subs[i+3], 10, 32)
		if err != nil {
			return
		}
		sid.SubAuthorities = append(sid.SubAuthorities, uint32(g))
	}
}

func MarshalInt32(number uint32) (bytes []byte){
	bytes = append(bytes, byte(number))
	bytes = append(bytes, byte(number >> 8))
	bytes = append(bytes, byte(number >> 16))
	bytes = append(bytes, byte(number >> 24))
	return bytes
}

const nullGUID = "00000000-0000-0000-0000-000000000000"

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g *GUID) FromBytes(b []byte) () {
	buf := bytes.NewBuffer(b)
	err := binary.Read(buf, binary.LittleEndian, &g.Data1)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &g.Data2)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &g.Data3)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.LittleEndian, &g.Data4)
	return
}

func (g *GUID) ToBytes() (b []byte) {
	buf := bytes.Buffer{}
	_ = binary.Write(&buf, binary.LittleEndian, g)
	// error not handle
	return buf.Bytes()
}

func (g *GUID) String() string {
	guid := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		g.Data1, g.Data2, g.Data3, g.Data4[0:2], g.Data4[2:8])
	if guid == nullGUID {
		guid = ""
	}
	return guid
}

func (g *GUID) FromString(str string) {
	strs := strings.Split(str, "-")
	g0, err := strconv.ParseUint(strs[0], 16, 32)
	if err != nil {
		return
	}
	g.Data1 = uint32(g0)

	g1, err := strconv.ParseUint(strs[1], 16, 16)
	if err != nil {
		return
	}
	g.Data2 = uint16(g1)

	g2, err := strconv.ParseUint(strs[2], 16, 16)
	if err != nil {
		return
	}
	g.Data3 = uint16(g2)

	g3, err := strconv.ParseUint(strs[3], 16, 16)
	if err != nil {
		return
	}

	b1 := make([]byte, 2)
	binary.BigEndian.PutUint16(b1,uint16(g3))

	b2 := make([]byte, 8)
	g4, err := strconv.ParseUint(strs[4], 16, 64)
	if err != nil {
		return
	}
	binary.BigEndian.PutUint64(b2,g4)
	copy(g.Data4[:],append(b1,b2[2:]...))
}