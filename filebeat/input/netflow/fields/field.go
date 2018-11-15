package fields

type FieldKey struct {
	EnterpriseID uint32
	FieldID      uint16
}

type Field struct {
	Key     FieldKey
	Name    string
	Decoder Decoder
}
