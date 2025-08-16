package enums

type KeyMethod string

const (
	KeyMethodNone        KeyMethod = "none"
	KeyMethodBLSKeyGen   KeyMethod = "bls_keygen"
)

type StoreKeyMethod string

const (
	KdfArgon2iMod StoreKeyMethod = "kdf:argon2i:mod"
	KdfArgon2iInt StoreKeyMethod = "kdf:argon2i:int"
	KdfRaw        StoreKeyMethod = "raw"
)