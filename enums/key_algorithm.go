package enums

type KeyAlgorithm string

const (
	KeyAlgAES128GCM       KeyAlgorithm = "a128gcm"
	KeyAlgAES256GCM       KeyAlgorithm = "a256gcm"
	KeyAlgAES128CBCHS256  KeyAlgorithm = "a128cbchs256"
	KeyAlgAES256CBCHS512  KeyAlgorithm = "a256cbchs512"
	KeyAlgAES128KW        KeyAlgorithm = "a128kw"
	KeyAlgAES256KW        KeyAlgorithm = "a256kw"
	KeyAlgAES128          KeyAlgorithm = "a128"
	KeyAlgAES256          KeyAlgorithm = "a256"
	KeyAlgBls12381G1      KeyAlgorithm = "bls12381g1"
	KeyAlgBls12381G2      KeyAlgorithm = "bls12381g2"
	KeyAlgBls12381G1G2    KeyAlgorithm = "bls12381g1g2"
	KeyAlgChacha20Poly1305 KeyAlgorithm = "c20p"
	KeyAlgChacha20XPoly1305 KeyAlgorithm = "xc20p"
	KeyAlgEd25519         KeyAlgorithm = "ed25519"
	KeyAlgX25519          KeyAlgorithm = "x25519"
	KeyAlgECP256          KeyAlgorithm = "p256"
	KeyAlgECP384          KeyAlgorithm = "p384"
	KeyAlgECSecp256k1     KeyAlgorithm = "k256"
	
	// Aliases for better readability
	KeyAlgAes128Gcm = KeyAlgAES128GCM
	KeyAlgAes256Gcm = KeyAlgAES256GCM
	KeyAlgP256 = KeyAlgECP256
	KeyAlgP384 = KeyAlgECP384
)