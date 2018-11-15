package fields

type Key struct {
	EnterpriseID uint32
	FieldID      uint16
}

type Field struct {
	Key
	Name    string
	Decoder Decoder
}
