package Exception

import (
	"fmt"
	"strings"
)

type Exception struct {
	Err error
	Explain string
}

func (e *Exception) IsNil () bool {
	if e.Err == nil && e.Explain == "" {
		return true
	} else {
		return false
	}
}

func (e *Exception) String() string {
	if e.Err != nil {
		return strings.ReplaceAll(fmt.Sprintf("%s , details: %s", e.Explain, e.Err),"\n","")
	}
	return fmt.Sprintf("%s", e.Explain)
}