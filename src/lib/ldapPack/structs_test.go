package ldapPack

import (
	"fmt"
	"testing"
)

func TestGUID(t *testing.T) {
	s := "88a9933e-e5c8-4f2a-9dd7-2527416b8092"
	var g1 = GUID{}
	g1.FromString(s)
	fmt.Println(g1.String())
}

func TestSID(t *testing.T) {
	// S-1-5-21-287611440-2308264118-3872617785-1105
	// S-1-5-90-0-2
	s := "S-1-5-90-0-2"
	var s1 = SID{}
	s1.FromString(s)
	fmt.Println(s1.String())
}