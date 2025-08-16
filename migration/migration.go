package migration

/*
#cgo CFLAGS: -I${SRCDIR}/../native
#cgo darwin LDFLAGS: -L${SRCDIR}/../native -laries_askar -framework Security -framework Foundation
#cgo linux LDFLAGS: -L${SRCDIR}/../native -laries_askar -lm -ldl

#include <stdint.h>
#include <stdlib.h>

extern int32_t askar_migrate_indy_sdk(const char* spec_uri, const char* wallet_name, const char* wallet_key, const char* kdf_level, void* callback, int64_t callback_id);
*/
import "C"
import (
	"unsafe"

	"github.com/Ajna-inc/askar-go/errors"
	"github.com/Ajna-inc/askar-go/ffi"
)

// KdfLevel represents the key derivation function level
// @dev Used to specify the security level for key derivation
type KdfLevel string

const (
	KdfLevelArgon2iMod KdfLevel = "argon2i:mod"
	KdfLevelArgon2iInt KdfLevel = "argon2i:int"
	KdfLevelRaw        KdfLevel = "raw"
)

// MigrateIndySdk migrates an Indy SDK wallet to Askar
// @param specURI The target database URI for the migrated wallet
// @param walletName The name of the Indy SDK wallet to migrate
// @param walletKey The encryption key for the Indy SDK wallet
// @param kdfLevel The key derivation function level to use
// @return Error if migration fails
func MigrateIndySdk(specURI, walletName, walletKey string, kdfLevel KdfLevel) error {
	callback := ffi.NewCallbackPromise()
	
	specURIStr := C.CString(specURI)
	defer C.free(unsafe.Pointer(specURIStr))
	
	walletNameStr := C.CString(walletName)
	defer C.free(unsafe.Pointer(walletNameStr))
	
	walletKeyStr := C.CString(walletKey)
	defer C.free(unsafe.Pointer(walletKeyStr))
	
	kdfLevelStr := C.CString(string(kdfLevel))
	defer C.free(unsafe.Pointer(kdfLevelStr))
	
	code := C.askar_migrate_indy_sdk(
		specURIStr,
		walletNameStr,
		walletKeyStr,
		kdfLevelStr,
		callback.Ptr(),
		C.int64_t(callback.ID()),
	)
	
	if code != 0 {
		return errors.HandleError(errors.ErrorCode(code), ffi.GetCurrentError)
	}
	
	result := callback.Wait()
	if result.ErrorCode != 0 {
		return errors.HandleError(errors.ErrorCode(result.ErrorCode), ffi.GetCurrentError)
	}
	
	return nil
}

// MigrationOptions provides options for migration
// @dev Encapsulates all parameters needed for wallet migration
type MigrationOptions struct {
	SpecURI    string   // @param Target database URI for migrated wallet
	WalletName string   // @param Name of the source Indy SDK wallet
	WalletKey  string   // @param Encryption key for the source wallet
	KdfLevel   KdfLevel // @param Security level for key derivation
}

// Migrate performs migration with options
// @param opts The migration options containing all parameters
// @return Error if migration fails
// @dev Defaults to KdfLevelArgon2iMod if KdfLevel not specified
func Migrate(opts MigrationOptions) error {
	if opts.KdfLevel == "" {
		opts.KdfLevel = KdfLevelArgon2iMod
	}
	
	return MigrateIndySdk(opts.SpecURI, opts.WalletName, opts.WalletKey, opts.KdfLevel)
}