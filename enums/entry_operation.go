package enums

type EntryOperation int32

const (
	EntryOperationInsert  EntryOperation = 0
	EntryOperationReplace EntryOperation = 1
	EntryOperationRemove  EntryOperation = 2
)