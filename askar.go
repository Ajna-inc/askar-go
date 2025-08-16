package askar

import (
	"github.com/Ajna-inc/askar-go/crypto"
	"github.com/Ajna-inc/askar-go/enums"
	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
	"github.com/Ajna-inc/askar-go/logging"
	"github.com/Ajna-inc/askar-go/migration"
	"github.com/Ajna-inc/askar-go/store"
)

// Key represents a cryptographic key with various operations
type (
	Key             = crypto.Key
	EncryptedBuffer = crypto.EncryptedBuffer
	AeadParams      = crypto.AeadParams
	// EcdhEs           = crypto.EcdhEs
	// Ecdh1PU          = crypto.Ecdh1PU
	// EcdhEsEncrypted  = crypto.EcdhEsEncrypted
	// Jwk              = crypto.Jwk
)

// Store represents a secure storage instance
type (
	Store    = store.Store
	Session  = store.Session
	Entry    = store.Entry
	KeyEntry = store.KeyEntry
	Scan     = store.Scan
)

// KeyAlgorithm defines supported cryptographic algorithms
type (
	KeyAlgorithm       = enums.KeyAlgorithm
	SignatureAlgorithm = enums.SignatureAlgorithm
	KeyMethod          = enums.KeyMethod
	StoreKeyMethod     = enums.StoreKeyMethod
	LogLevel           = enums.LogLevel
	EntryOperation     = enums.EntryOperation
)

// AskarError represents library-specific errors
type (
	AskarError = errors.AskarError
	ErrorCode  = errors.ErrorCode
)

// Constants for cryptographic algorithms and operations
const (
	// Key Algorithms
	KeyAlgAES128GCM         = enums.KeyAlgAES128GCM
	KeyAlgAES256GCM         = enums.KeyAlgAES256GCM
	KeyAlgAES128CBCHS256    = enums.KeyAlgAES128CBCHS256
	KeyAlgAES256CBCHS512    = enums.KeyAlgAES256CBCHS512
	KeyAlgAES128KW          = enums.KeyAlgAES128KW
	KeyAlgAES256KW          = enums.KeyAlgAES256KW
	KeyAlgBls12381G1        = enums.KeyAlgBls12381G1
	KeyAlgBls12381G2        = enums.KeyAlgBls12381G2
	KeyAlgBls12381G1G2      = enums.KeyAlgBls12381G1G2
	KeyAlgChacha20Poly1305  = enums.KeyAlgChacha20Poly1305
	KeyAlgChacha20XPoly1305 = enums.KeyAlgChacha20XPoly1305
	KeyAlgEd25519           = enums.KeyAlgEd25519
	KeyAlgX25519            = enums.KeyAlgX25519
	KeyAlgECP256            = enums.KeyAlgECP256
	KeyAlgECP384            = enums.KeyAlgECP384
	KeyAlgECSecp256k1       = enums.KeyAlgECSecp256k1

	// Signature Algorithms
	SignatureAlgEdDSA  = enums.SignatureAlgEdDSA
	SignatureAlgES256  = enums.SignatureAlgES256
	SignatureAlgES384  = enums.SignatureAlgES384
	SignatureAlgES256K = enums.SignatureAlgES256K

	// Key Methods
	KeyMethodNone      = enums.KeyMethodNone
	KeyMethodBLSKeyGen = enums.KeyMethodBLSKeyGen

	// Store Key Methods
	KdfArgon2iMod = enums.KdfArgon2iMod
	KdfArgon2iInt = enums.KdfArgon2iInt
	KdfRaw        = enums.KdfRaw

	// Log Levels
	LogLevelError = enums.LogLevelError
	LogLevelWarn  = enums.LogLevelWarn
	LogLevelInfo  = enums.LogLevelInfo
	LogLevelDebug = enums.LogLevelDebug
	LogLevelTrace = enums.LogLevelTrace

	// Entry Operations
	EntryOperationInsert  = enums.EntryOperationInsert
	EntryOperationReplace = enums.EntryOperationReplace
	EntryOperationRemove  = enums.EntryOperationRemove

	// Error Codes
	ErrorCodeSuccess     = errors.ErrorCodeSuccess
	ErrorCodeBackend     = errors.ErrorCodeBackend
	ErrorCodeBusy        = errors.ErrorCodeBusy
	ErrorCodeDuplicate   = errors.ErrorCodeDuplicate
	ErrorCodeEncryption  = errors.ErrorCodeEncryption
	ErrorCodeInput       = errors.ErrorCodeInput
	ErrorCodeNotFound    = errors.ErrorCodeNotFound
	ErrorCodeUnexpected  = errors.ErrorCodeUnexpected
	ErrorCodeUnsupported = errors.ErrorCodeUnsupported
	ErrorCodeCustom      = errors.ErrorCodeCustom
)

// Key Functions
var (
	GenerateKey        = crypto.Generate
	KeyFromSeed        = crypto.FromSeed
	KeyFromSecretBytes = crypto.FromSecretBytes
	KeyFromPublicBytes = crypto.FromPublicBytes
	KeyFromJWK         = crypto.FromJWK
	// KeyFromKeyExchange  = crypto.FromKeyExchange
	// JwkFromKey          = crypto.JwkFromKey
)

// CryptoBox Functions - Reserved for future implementation
// var (
// 	CryptoBox             = crypto.CryptoBox
// 	CryptoBoxOpen         = crypto.CryptoBoxOpen
// 	CryptoBoxRandomNonce  = crypto.CryptoBoxRandomNonce
// 	CryptoBoxSeal         = crypto.CryptoBoxSeal
// 	CryptoBoxSealOpen     = crypto.CryptoBoxSealOpen
// )

// Store Functions
var (
	StoreProvision      = store.Provision
	StoreOpen           = store.Open
	StoreRemove         = store.Remove
	StoreGenerateRawKey = store.GenerateRawKey
)

// Migration Functions
var (
	MigrateIndySdk = migration.MigrateIndySdk
	Migrate        = migration.Migrate
)

// Logging Functions
var (
	SetMaxLogLevel    = logging.SetMaxLogLevel
	SetDefaultLogger  = logging.SetDefaultLogger
	SetCustomLogger   = logging.SetCustomLogger
	ClearCustomLogger = logging.ClearCustomLogger
	DefaultLoggerFunc = logging.DefaultLogger
)

// Version returns the Askar library version
func Version() (string, error) {
	return ffi.Version()
}

// GetCurrentError returns the current error from the library
func GetCurrentError() string {
	return ffi.GetCurrentError()
}
