package Scanners

import (
	"LDAPToolkit/src/lib/constants"
	"strings"
)

func ConvertSid(s string) string {
	res := s
	for key,value := range constants.SidMap {
		res = strings.ReplaceAll(res,key,value)
	}
	return res
}

func ConvertDN(s string, rootDN string) string {
	return strings.ReplaceAll(s,"<rootDN>",rootDN)
}

func ConvertRight(strRights []string) [][]uint8{
	var rights [][]uint8
	for _,r := range strRights {
		right,ok1 := constants.AdRights[r]
		adRight,ok2 := constants.AdsSpecRights[r]
		fileRight,ok3 := constants.FileSpecRights[r]
		if ok1{
			rights = append(rights, right)
		}else if ok2 {
			rights = append(rights, adRight)
		}else if ok3 {
			rights = append(rights, fileRight)
		}
	}
	return rights
}

func CheckRights(accessMask uint32,rule []uint8) bool {
	if len(rule) == 0 {
		return true
	}

	//if accessMask == BitMapCalculate(rule) {
	//	return true
	//}

	if len(rule) == 1 {
		if CheckMask(accessMask, uint32(rule[0])) {
			return true
		}
	} else {
		for _,r := range rule {
			if !CheckMask(accessMask, uint32(r)) {
				return false
			}
		}
		return true
	}
	//for _,r := range rule {
	//	//if BitMapCalculate([]uint8{r}) == accessMask {
	//	if CheckMask(accessMask, uint32(r)) {
	//		return true
	//	}
	//}
	return false
}

func CheckMask(accessMask uint32,mask uint32) bool{
	return accessMask&(1<<mask) == (1<<mask)
}

func CheckMergedRights(accessMask uint32, rights [][]uint8) bool{
	for _,right := range rights {
		for _,bit := range right{
			if !CheckMask(accessMask,uint32(bit)){
				return false
			}
		}
	}
	return true
}

func BitMapCalculate(bitmaps []uint8) (accessMask uint32) {
	for _,bit := range bitmaps {
		accessMask = accessMask|(1<<bit)
	}
	return
}

