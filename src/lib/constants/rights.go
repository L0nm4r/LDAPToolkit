package constants

// ObjectSpecial Access Rights
const (
	CreateChild uint8 = iota
	DeleteChild
	ListChildren
	Self
	ReadProperty
	WriteProperty
	DeleteTree
	ListObject
	ExtendedRight
)
// Standard Access Rights
const (
	Delete	uint8 = iota + 16
	ReadControl
	WriteDacl
	WriteOwner
	Synchronize
)
const AccessSystemSecurity = 24

var AdRights = map[string] []uint8 {
	// ObjectSpecial Access Rights
	"CreateChild":   {CreateChild},
	"DeleteChild":   {DeleteChild},
	"ListChildren":  {ListChildren},
	"Self":          {Self},
	"ReadProperty": {ReadProperty},
	"WriteProperty": {WriteProperty},
	"DeleteTree":    {DeleteTree},
	"ListObject":    {ListObject},
	"ExtendedRight": {ExtendedRight},
	// Standard Access Rights
	"Delete": {Delete},
	"ReadControl": {ReadControl},
	"WriteDacl": {WriteDacl},
	"WriteOwner": {WriteOwner},
	"Synchronize": {Synchronize},
	// AS
	"AccessSystemSecurity": {AccessSystemSecurity},
	// Generic Rights
	"GenericExecute": {ReadControl, ListChildren},
	"GenericWrite": {ReadControl, Self},
	"GenericRead":    {ReadControl, ListObject, ReadProperty, ListChildren},
	"GenericAll": {CreateChild, DeleteChild, ListChildren, Self, ReadProperty, WriteProperty,
		DeleteTree, ListObject, ExtendedRight, Delete, ReadControl, WriteDacl, WriteOwner},
}

const (
	FILE_READ_DATA   uint8 = iota // FILE_LIST_DIRECTORY
	FILE_WRITE_DATA                   // FILE_ADD_FILE
	FILE_APPEND_DATA                  // FILE_ADD_SUBDIRECTORY
	FILE_READ_EA
	FILE_WRITE_EA
	FILE_EXECUTE // FILE_TRAVERSE
	FILE_DELETE_CHILD
	FILE_READ_ATTRIBUTES
	FILE_WRITE_ATTRIBUTES
)

var FileSpecRights = map[string][]uint8{
	"FILE_READ_DATA": {FILE_READ_DATA},
	"FILE_WRITE_DATA": {FILE_WRITE_DATA},
	"FILE_APPEND_DATA": {FILE_APPEND_DATA},
	"FILE_READ_EA": {FILE_READ_EA},
	"FILE_WRITE_EA": {FILE_WRITE_EA},
	"FILE_EXECUTE": {FILE_EXECUTE},
	"FILE_DELETE_CHILD": {FILE_DELETE_CHILD},
	"FILE_READ_ATTRIBUTES": {FILE_READ_ATTRIBUTES},
	"FILE_WRITE_ATTRIBUTES": {FILE_WRITE_ATTRIBUTES},
}

const (
	ADS_RIGHT_DS_CREATE_CHILD  uint8 = iota
	ADS_RIGHT_DS_DELETE_CHILD
	ADS_RIGHT_ACTRL_DS_LIST
	ADS_RIGHT_DS_SELF
	ADS_RIGHT_DS_READ_PROP
	ADS_RIGHT_DS_WRITE_PROP
	ADS_RIGHT_DS_DELETE_TREE
	ADS_RIGHT_DS_LIST_OBJECT
	ADS_RIGHT_DS_CONTROL_ACCESS
)

var AdsSpecRights = map[string][]uint8{
	"ADS_RIGHT_DS_CREATE_CHILD": {ADS_RIGHT_DS_CREATE_CHILD},
	"ADS_RIGHT_DS_DELETE_CHILD": {ADS_RIGHT_DS_DELETE_CHILD},
	"ADS_RIGHT_ACTRL_DS_LIST": {ADS_RIGHT_ACTRL_DS_LIST},
	"ADS_RIGHT_DS_SELF": {ADS_RIGHT_DS_SELF},
	"ADS_RIGHT_DS_READ_PROP": {ADS_RIGHT_DS_READ_PROP},
	"ADS_RIGHT_DS_WRITE_PROP": {ADS_RIGHT_DS_WRITE_PROP},
	"ADS_RIGHT_DS_DELETE_TREE": {ADS_RIGHT_DS_DELETE_TREE},
	"ADS_RIGHT_DS_LIST_OBJECT": {ADS_RIGHT_DS_LIST_OBJECT},
	"ADS_RIGHT_DS_CONTROL_ACCESS": {ADS_RIGHT_DS_CONTROL_ACCESS},
}