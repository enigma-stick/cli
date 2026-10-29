// Package enigma wraps the Enigma host library's C API. Build the Rust library
// with `cargo build --manifest-path ../enigma-host/Cargo.toml` first.
package enigma

/*
#cgo CFLAGS: -I${SRCDIR}/../../enigma-host/include
#cgo LDFLAGS: -L${SRCDIR}/../../enigma-host/target/debug -lenigma -Wl,-rpath,${SRCDIR}/../../enigma-host/target/debug
#include <stdlib.h>
#include "enigma.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"
)

// Error preserves both the host-library category and any device error code.
type Error struct {
	Code       int32
	DeviceCode uint32
	Message    string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("enigma error %d (device code %d)", e.Code, e.DeviceCode)
}

const (
	InvalidArg         int32 = C.ENIGMA_INVALID_ARG
	DeviceNotFound     int32 = C.ENIGMA_DEVICE_NOT_FOUND
	MultipleDevices    int32 = C.ENIGMA_MULTIPLE_DEVICES
	IncompatibleDevice int32 = C.ENIGMA_INCOMPATIBLE_DEVICE
	USBError           int32 = C.ENIGMA_USB_ERROR
	ProtocolError      int32 = C.ENIGMA_PROTOCOL_ERROR
	DeviceError        int32 = C.ENIGMA_DEVICE_ERROR
	InternalError      int32 = C.ENIGMA_INTERNAL_ERROR
	MalformedOutput    int32 = C.ENIGMA_MALFORMED_OUTPUT
	BufferTooSmall     int32 = C.ENIGMA_BUFFER_TOO_SMALL
)

func resultError(code C.enigma_result, detail C.enigma_error) error {
	if code == C.ENIGMA_OK {
		return nil
	}
	return &Error{
		Code:       int32(code),
		DeviceCode: uint32(detail.device_code),
		Message:    C.GoString(&detail.message[0]),
	}
}

type TokenState uint32
type SessionState uint32

const (
	TokenUninitialized   TokenState   = 0
	TokenProvisioning    TokenState   = 1
	TokenReady           TokenState   = 2
	SessionClosed        SessionState = 0
	SessionAuthenticated SessionState = 1
	SessionFault         SessionState = 2
)

type StatusInfo struct {
	Token   TokenState
	Session SessionState
}

type KeyType uint32
type KeyUsage uint32

const (
	KeyAES       KeyType  = C.enigma_key_type_aes
	KeyRSA       KeyType  = C.enigma_key_type_rsa
	KeyEC        KeyType  = C.enigma_key_type_ec
	KeyHMAC      KeyType  = C.enigma_key_type_hmac
	UsageEncrypt KeyUsage = C.enigma_key_usage_encrypt
	UsageSign    KeyUsage = C.enigma_key_usage_sign
	UsageDerive  KeyUsage = C.enigma_key_usage_derive
)

// String returns the key type name, or a numeric representation for an
// unrecognized value returned by a newer device.
func (t KeyType) String() string {
	switch t {
	case KeyAES:
		return "AES"
	case KeyRSA:
		return "RSA"
	case KeyEC:
		return "EC"
	case KeyHMAC:
		return "HMAC"
	default:
		return fmt.Sprintf("KeyType(%d)", uint32(t))
	}
}

// ParseKeyType accepts a key type name, ignoring letter case.
func ParseKeyType(s string) (KeyType, error) {
	switch strings.ToUpper(s) {
	case "AES":
		return KeyAES, nil
	case "RSA":
		return KeyRSA, nil
	case "EC":
		return KeyEC, nil
	case "HMAC":
		return KeyHMAC, nil
	default:
		return 0, fmt.Errorf("unknown key type %q (want AES, RSA, EC, or HMAC)", s)
	}
}

// String returns the key usage name, or a numeric representation for an
// unrecognized value returned by a newer device.
func (u KeyUsage) String() string {
	switch u {
	case UsageEncrypt:
		return "ENCRYPT"
	case UsageSign:
		return "SIGN"
	case UsageDerive:
		return "DERIVE"
	default:
		return fmt.Sprintf("KeyUsage(%d)", uint32(u))
	}
}

// ParseKeyUsage accepts a key usage name, ignoring letter case.
func ParseKeyUsage(s string) (KeyUsage, error) {
	switch strings.ToUpper(s) {
	case "ENCRYPT":
		return UsageEncrypt, nil
	case "SIGN":
		return UsageSign, nil
	case "DERIVE":
		return UsageDerive, nil
	default:
		return 0, fmt.Errorf("unknown key usage %q (want ENCRYPT, SIGN, or DERIVE)", s)
	}
}

type Key struct {
	ID        uint32
	Type      KeyType
	Usage     KeyUsage
	Size      uint16
	Label     string
	CreatedAt uint32 // Unix seconds supplied by the host at creation.
}

// KeyFilter fields are optional. An ID takes precedence over other filters on
// the device. A nil filter lists all keys.
type KeyFilter struct {
	Type  *KeyType
	Usage *KeyUsage
	Label *string
	ID    *uint32
}

type ECDHResult struct {
	KeyID uint32
	Salt  []byte
	Info  string
}

// Device serializes requests because the wire protocol has no request IDs.
// Close must be called when the device is no longer needed.
type Device struct {
	mu  sync.Mutex
	ptr *C.enigma_device
}

func Open() (*Device, error) {
	var ptr *C.enigma_device
	var detail C.enigma_error
	if err := resultError(C.enigma_open(&ptr, &detail), detail); err != nil {
		return nil, err
	}
	if ptr == nil {
		return nil, errors.New("enigma_open returned a nil device")
	}
	return &Device{ptr: ptr}, nil
}

func (d *Device) call(fn func(*C.enigma_device, *C.enigma_error) C.enigma_result) error {
	if d == nil {
		return errors.New("nil enigma device")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ptr == nil {
		return errors.New("enigma device is closed")
	}
	var detail C.enigma_error
	return resultError(fn(d.ptr, &detail), detail)
}

func (d *Device) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ptr == nil {
		return nil
	}
	ptr := d.ptr
	d.ptr = nil // The C call consumes the handle even if closing reports an error.
	var detail C.enigma_error
	return resultError(C.enigma_close(ptr, &detail), detail)
}

func (d *Device) Status() (StatusInfo, error) {
	var raw C.enigma_status_info
	err := d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_status(p, &raw, e)
	})
	return StatusInfo{TokenState(raw.token_state), SessionState(raw.session_state)}, err
}

func cString(s string) (*C.char, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, errors.New("string contains NUL byte")
	}
	return C.CString(s), nil
}

func (d *Device) Authenticate(pin string) error {
	cs, err := cString(pin)
	if err != nil {
		return err
	}
	defer C.free(unsafe.Pointer(cs))
	return d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_authenticate(p, cs, e)
	})
}

func (d *Device) Lock() error {
	return d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_lock(p, e)
	})
}

func (d *Device) GenerateKey(kind KeyType, usage KeyUsage, size uint16, label string) (uint32, error) {
	cs, err := cString(label)
	if err != nil {
		return 0, err
	}
	defer C.free(unsafe.Pointer(cs))
	var id C.uint32_t
	err = d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_generate_key(p, C.enigma_key_type(kind), C.enigma_key_usage(usage), C.uint16_t(size), cs, &id, e)
	})
	return uint32(id), err
}

func bytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// The C API does not provide a size query for these operations. Its wire
// response length is uint16, so one maximum-size buffer avoids replaying a
// stateful operation after a buffer-too-small result.
const maxOutput = 65535

func (d *Device) Encrypt(id uint32, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext is empty")
	}
	out := make([]byte, maxOutput)
	var n C.size_t
	err := d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_encrypt(p, C.uint32_t(id), bytePtr(plaintext), C.size_t(len(plaintext)), bytePtr(out), C.size_t(len(out)), &n, e)
	})
	if err != nil {
		return nil, err
	}
	if n > C.size_t(len(out)) {
		return nil, errors.New("enigma returned an invalid ciphertext length")
	}
	return out[:int(n):int(n)], nil
}

func (d *Device) Decrypt(id uint32, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext is empty")
	}
	out := make([]byte, maxOutput)
	var n C.size_t
	err := d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_decrypt(p, C.uint32_t(id), bytePtr(ciphertext), C.size_t(len(ciphertext)), bytePtr(out), C.size_t(len(out)), &n, e)
	})
	if err != nil {
		return nil, err
	}
	if n > C.size_t(len(out)) {
		return nil, errors.New("enigma returned an invalid plaintext length")
	}
	return out[:int(n):int(n)], nil
}

func (d *Device) Sign(id uint32, message []byte) ([]byte, error) {
	// The C API accepts a zero-length message but still requires a non-null pointer.
	if len(message) == 0 {
		message = []byte{0}[:0]
	}
	out := make([]byte, maxOutput)
	var n C.size_t
	err := d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		input := bytePtr(message)
		if input == nil {
			input = bytePtr(out)
		}
		return C.enigma_sign(p, C.uint32_t(id), input, C.size_t(len(message)), bytePtr(out), C.size_t(len(out)), &n, e)
	})
	if err != nil {
		return nil, err
	}
	if n > C.size_t(len(out)) {
		return nil, errors.New("enigma returned an invalid signature length")
	}
	return out[:int(n):int(n)], nil
}

// Verify supports HMAC keys in the current firmware.
func (d *Device) Verify(id uint32, message, signature []byte) (bool, error) {
	if len(message) == 0 || len(signature) == 0 {
		return false, errors.New("message and signature must be nonempty")
	}
	var verified C.bool
	err := d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_verify(p, C.uint32_t(id), bytePtr(message), C.size_t(len(message)), bytePtr(signature), C.size_t(len(signature)), &verified, e)
	})
	return bool(verified), err
}

func (d *Device) ECDH(privateKeyID uint32, peerSPKIDER []byte, label string) (ECDHResult, error) {
	if len(peerSPKIDER) == 0 {
		return ECDHResult{}, errors.New("peer public key is empty")
	}
	cs, err := cString(label)
	if err != nil {
		return ECDHResult{}, err
	}
	defer C.free(unsafe.Pointer(cs))
	var raw *C.enigma_ecdh_result
	err = d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_ecdh(p, C.uint32_t(privateKeyID), C.enigma_public_key_encoding(C.enigma_public_key_encoding_der_spki), bytePtr(peerSPKIDER), C.size_t(len(peerSPKIDER)), cs, &raw, e)
	})
	if err != nil {
		return ECDHResult{}, err
	}
	if raw == nil {
		return ECDHResult{}, errors.New("enigma returned a nil ECDH result")
	}
	defer C.enigma_ecdh_free(raw)
	if raw.salt_len > maxOutput {
		return ECDHResult{}, errors.New("enigma returned an invalid salt length")
	}
	return ECDHResult{KeyID: uint32(raw.key_id), Salt: C.GoBytes(unsafe.Pointer(raw.salt), C.int(raw.salt_len)), Info: C.GoString(raw.info)}, nil
}

func (d *Device) ExportPublicKey(id uint32) ([]byte, error) {
	var needed C.size_t
	err := d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		code := C.enigma_export_public_key(p, C.uint32_t(id), nil, 0, &needed, e)
		if code != C.ENIGMA_BUFFER_TOO_SMALL {
			return code
		}
		if needed == 0 || needed > maxOutput {
			return C.ENIGMA_MALFORMED_OUTPUT
		}
		return C.ENIGMA_OK
	})
	if err != nil {
		return nil, err
	}
	if needed == 0 {
		return []byte{}, nil
	}
	out := make([]byte, int(needed))
	var n C.size_t
	err = d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_export_public_key(p, C.uint32_t(id), bytePtr(out), C.size_t(len(out)), &n, e)
	})
	if err != nil {
		return nil, err
	}
	if n > C.size_t(len(out)) {
		return nil, errors.New("enigma returned an invalid public key length")
	}
	return out[:int(n):int(n)], nil
}

func (d *Device) ListKeys(filter *KeyFilter) ([]Key, error) {
	var typ *C.enigma_key_type
	var usage *C.enigma_key_usage
	var label *C.char
	var id *C.uint32_t
	var ct C.enigma_key_type
	var cu C.enigma_key_usage
	var ci C.uint32_t
	if filter != nil {
		if filter.Type != nil {
			ct = C.enigma_key_type(*filter.Type)
			typ = &ct
		}
		if filter.Usage != nil {
			cu = C.enigma_key_usage(*filter.Usage)
			usage = &cu
		}
		if filter.ID != nil {
			ci = C.uint32_t(*filter.ID)
			id = &ci
		}
		if filter.Label != nil {
			var err error
			label, err = cString(*filter.Label)
			if err != nil {
				return nil, err
			}
			defer C.free(unsafe.Pointer(label))
		}
	}
	var raw *C.enigma_key_list
	err := d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_list_keys(p, typ, usage, label, id, &raw, e)
	})
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New("enigma returned a nil key list")
	}
	defer C.enigma_key_list_free(raw)
	if raw.count > maxOutput {
		return nil, errors.New("enigma returned an invalid key count")
	}
	if raw.count > 0 && raw.keys == nil {
		return nil, errors.New("enigma returned missing key entries")
	}
	entries := unsafe.Slice(raw.keys, int(raw.count))
	keys := make([]Key, len(entries))
	for i, k := range entries {
		keys[i] = Key{uint32(k.id), KeyType(k._type), KeyUsage(k.usage), uint16(k.size), C.GoString(k.label), uint32(k.created_at)}
	}
	return keys, nil
}

func (d *Device) DestroyKey(id uint32) error {
	return d.call(func(p *C.enigma_device, e *C.enigma_error) C.enigma_result {
		return C.enigma_destroy_key(p, C.uint32_t(id), e)
	})
}
