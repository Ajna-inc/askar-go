package enums

type SignatureAlgorithm string

const (
	SignatureAlgEdDSA      SignatureAlgorithm = "eddsa"
	SignatureAlgES256      SignatureAlgorithm = "es256"
	SignatureAlgES384      SignatureAlgorithm = "es384"
	SignatureAlgES256K     SignatureAlgorithm = "es256k"
)