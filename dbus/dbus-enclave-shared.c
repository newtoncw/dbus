#include "sgx_eid.h"
#include "sgx_urts.h"

const char* _dbus_enclave_shared_error_translate(sgx_status_t status) {
	switch(status) {
		case SGX_ERROR_UNEXPECTED: return "SGX ERROR: Unexpected error";
		case SGX_ERROR_INVALID_PARAMETER: return "SGX ERROR: The parameter is incorrect";
		case SGX_ERROR_OUT_OF_MEMORY: return "SGX ERROR: Not enough memory is available to complete this operation";
		case SGX_ERROR_ENCLAVE_LOST: return "SGX ERROR: Enclave lost after power transition or used in child process created by linux:fork()";
		case SGX_ERROR_INVALID_STATE: return "SGX ERROR: SGX API is invoked in incorrect order or state";
		//case SGX_ERROR_FEATURE_NOT_SUPPORTED: return "SGX ERROR: Feature is not supported on this platform";
		//case SGX_PTHREAD_EXIT: return "SGX ERROR: Enclave is exited with pthread_exit()";
		case SGX_ERROR_INVALID_FUNCTION: return "SGX ERROR: The ecall/ocall index is invalid";
		case SGX_ERROR_OUT_OF_TCS: return "SGX ERROR: The enclave is out of TCS";
		case SGX_ERROR_ENCLAVE_CRASHED: return "SGX ERROR: The enclave is crashed";
		case SGX_ERROR_ECALL_NOT_ALLOWED: return "SGX ERROR: The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization";
		case SGX_ERROR_OCALL_NOT_ALLOWED: return "SGX ERROR: The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling";
		case SGX_ERROR_STACK_OVERRUN: return "SGX ERROR: The enclave is running out of stack";
		case SGX_ERROR_UNDEFINED_SYMBOL: return "SGX ERROR: The enclave image has undefined symbol";
		case SGX_ERROR_INVALID_ENCLAVE: return "SGX ERROR: The enclave image is not correct";
		case SGX_ERROR_INVALID_ENCLAVE_ID: return "SGX ERROR: The enclave id is invalid";
		case SGX_ERROR_INVALID_SIGNATURE: return "SGX ERROR: The signature is invalid";
		case SGX_ERROR_NDEBUG_ENCLAVE: return "SGX ERROR: The enclave is signed as product enclave, and can not be created as debuggable enclave";
		case SGX_ERROR_OUT_OF_EPC: return "SGX ERROR: Not enough EPC is available to load the enclave";
		case SGX_ERROR_NO_DEVICE: return "SGX ERROR: Can't open SGX device";
		case SGX_ERROR_MEMORY_MAP_CONFLICT: return "SGX ERROR: Page mapping failed in driver";
		case SGX_ERROR_INVALID_METADATA: return "SGX ERROR: The metadata is incorrect";
		case SGX_ERROR_DEVICE_BUSY: return "SGX ERROR: Device is busy, mostly EINIT failed";
		case SGX_ERROR_INVALID_VERSION: return "SGX ERROR: Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform";
		case SGX_ERROR_MODE_INCOMPATIBLE: return "SGX ERROR: The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS";
		case SGX_ERROR_ENCLAVE_FILE_ACCESS: return "SGX ERROR: Can't open enclave file";
		case SGX_ERROR_INVALID_MISC: return "SGX ERROR: The MiscSelct/MiscMask settings are not correct";
		case SGX_ERROR_INVALID_LAUNCH_TOKEN: return "SGX ERROR: The launch token is not correct";
		case SGX_ERROR_MAC_MISMATCH: return "SGX ERROR: Indicates verification error for reports, sealed datas, etc";
		case SGX_ERROR_INVALID_ATTRIBUTE: return "SGX ERROR: The enclave is not authorized";
		case SGX_ERROR_INVALID_CPUSVN: return "SGX ERROR: The cpu svn is beyond platform's cpu svn value";
		case SGX_ERROR_INVALID_ISVSVN: return "SGX ERROR: The isv svn is greater than the enclave's isv svn";
		case SGX_ERROR_INVALID_KEYNAME: return "SGX ERROR: The key name is an unsupported value";
		case SGX_ERROR_SERVICE_UNAVAILABLE: return "SGX ERROR: Indicates aesm didn't respond or the requested service is not supported";
		case SGX_ERROR_SERVICE_TIMEOUT: return "SGX ERROR: The request to aesm timed out";
		case SGX_ERROR_AE_INVALID_EPIDBLOB: return "SGX ERROR: Indicates epid blob verification error";
		case SGX_ERROR_SERVICE_INVALID_PRIVILEGE: return "SGX ERROR: Enclave has no privilege to get launch token";
		case SGX_ERROR_EPID_MEMBER_REVOKED: return "SGX ERROR: The EPID group membership is revoked";
		case SGX_ERROR_UPDATE_NEEDED: return "SGX ERROR: SGX needs to be updated";
		case SGX_ERROR_NETWORK_FAILURE: return "SGX ERROR: Network connecting or proxy setting issue is encountered";
		case SGX_ERROR_AE_SESSION_INVALID: return "SGX ERROR: Session is invalid or ended by server";
		case SGX_ERROR_BUSY: return "SGX ERROR: The requested service is temporarily not availabe";
		case SGX_ERROR_MC_NOT_FOUND: return "SGX ERROR: The Monotonic Counter doesn't exist or has been invalided";
		case SGX_ERROR_MC_NO_ACCESS_RIGHT: return "SGX ERROR: Caller doesn't have the access right to specified VMC";
		case SGX_ERROR_MC_USED_UP: return "SGX ERROR: Monotonic counters are used out";
		case SGX_ERROR_MC_OVER_QUOTA: return "SGX ERROR: Monotonic counters exceeds quota limitation";
		case SGX_ERROR_KDF_MISMATCH: return "SGX ERROR: Key derivation function doesn't match during key exchange";
		case SGX_ERROR_UNRECOGNIZED_PLATFORM: return "SGX ERROR: EPID Provisioning failed due to platform not recognized by backend server";
		//case SGX_ERROR_UNSUPPORTED_CONFIG: return "SGX ERROR: The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid";
		case SGX_ERROR_NO_PRIVILEGE: return "SGX ERROR: Not enough privilege to perform the operation";
		case SGX_ERROR_PCL_ENCRYPTED: return "SGX ERROR: trying to encrypt an already encrypted enclave";
		case SGX_ERROR_PCL_NOT_ENCRYPTED: return "SGX ERROR: trying to load a plain enclave using sgx_create_encrypted_enclave";
		case SGX_ERROR_PCL_MAC_MISMATCH: return "SGX ERROR: section mac result does not match build time mac";
		case SGX_ERROR_PCL_SHA_MISMATCH: return "SGX ERROR: Unsealed key MAC does not match MAC of key hardcoded in enclave binary";
		case SGX_ERROR_PCL_GUID_MISMATCH: return "SGX ERROR: GUID in sealed blob does not match GUID hardcoded in enclave binary";
		case SGX_ERROR_FILE_BAD_STATUS: return "SGX ERROR: The file is in bad status, run sgx_clearerr to try and fix it";
		case SGX_ERROR_FILE_NO_KEY_ID: return "SGX ERROR: The Key ID field is all zeros, can't re-generate the encryption key";
		case SGX_ERROR_FILE_NAME_MISMATCH: return "SGX ERROR: The current file name is different then the original file name (not allowed, substitution attack)";
		case SGX_ERROR_FILE_NOT_SGX_FILE: return "SGX ERROR: The file is not an SGX file";
		case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE: return "SGX ERROR: A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)";
		case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE: return "SGX ERROR: A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)";
		case SGX_ERROR_FILE_RECOVERY_NEEDED: return "SGX ERROR: When openeing the file, recovery is needed, but the recovery process failed";
		case SGX_ERROR_FILE_FLUSH_FAILED: return "SGX ERROR: fflush operation (to disk) failed (only used when no EXXX is returned)";
		case SGX_ERROR_FILE_CLOSE_FAILED: return "SGX ERROR: fclose operation (to disk) failed (only used when no EXXX is returned)";
		//case SGX_ERROR_UNSUPPORTED_ATT_KEY_ID: return "SGX ERROR: platform quoting infrastructure does not support the key";
		//case SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE: return "SGX ERROR: Failed to generate and certify the attestation key";
		//case SGX_ERROR_ATT_KEY_UNINITIALIZED: return "SGX ERROR: The platform quoting infrastructure does not have the attestation key available to generate quote";
		//case SGX_ERROR_INVALID_ATT_KEY_CERT_DATA: return "SGX ERROR: The data returned by the platform library's sgx_get_quote_config() is invalid";
		//case SGX_ERROR_PLATFORM_CERT_UNAVAILABLE: return "SGX ERROR: The PCK Cert for the platform is not available";
		case SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED: return "SGX ERROR: The ioctl for enclave_create unexpectedly failed with EINTR";
		default: return "";
	}
}

sgx_status_t _dbus_enclave_internal_encrypt_message(uint64_t eid, char *uid, uint8_t* message, size_t message_size, sgx_aes_gcm_data_t* response, size_t response_size) {
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;
	status2 = ecall_encrypt(eid, uid, message, message_size, response, response_size, &status);

	if(status != SGX_SUCCESS) {
		return status;
	} else {
		return status2;
	}
}

sgx_status_t _dbus_enclave_internal_decrypt_message(uint64_t eid, char *uid, sgx_aes_gcm_data_t* message, size_t message_size, uint8_t* response, size_t response_size) {
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;
	status2 = ecall_decrypt(eid, uid, message, message_size, response, response_size, &status);

	if(status != SGX_SUCCESS) {
		return status;
	} else {
		return status2;
	}
}

void _dbus_enclave_shared_encrypt_message(DBusTrustedSession *session, DBusMessage *message, DBusError *error) {
	return;

	DBusString *str = message->body;
	DBUS_STRING_PREAMBLE (str);
	uint64_t total_size = real->len;

	if(total_size > 0) {
		uint8_t* payload = real->str;
		uint64_t response_size = sizeof(sgx_aes_gcm_data_t) + total_size;
		uint8_t* response = malloc(response_size + 1);

		sgx_status_t status = SGX_SUCCESS;
		status2 = ecall_encrypt(session->connection->enclave_id, session->tdbus_uid, payload, total_size, (sgx_aes_gcm_data_t*)response, response_size);

		if(status != SGX_SUCCESS) {
			dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(status));
			return;
		}

		//set new body. How????
		real->len = response_size;
		real->allocated = response_size + 1;
		real->str = response;
		real->str[response_size] = '\0';
	}
}

void _dbus_enclave_shared_decrypt_message(DBusTrustedSession *session, DBusMessage *message, DBusError *error) {
	return;

	DBusString *str = message->body;
	DBUS_STRING_PREAMBLE (str);
	uint64_t total_size = real->len;

	if(total_size > 0) {
		uint8_t* cipher = real->str;
		uint64_t response_size = total_size - sizeof(sgx_aes_gcm_data_t);
		uint8_t* response = malloc(response_size + 1);

		sgx_status_t status = SGX_SUCCESS;
		status = ecall_decrypt(session->connection->enclave_id, session->tdbus_uid, (sgx_aes_gcm_data_t*)cipher, total_size, response, response_size);

		if(status != SGX_SUCCESS) {
			dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(status));
			return;
		}

		//set new body. How????
		real->len = response_size;
		real->allocated = response_size + 1;
		real->str = response;
		real->str[response_size] = '\0';
	}
}

sgx_status_t _dbus_enclave_shared_close_session(uint64_t eid, char *uid) {
	return ecall_close_session(eid, uid);
}
