//go:build windows

package chromium

import (
	"errors"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// markerKey remembers which values in each policy key are ours (as SPKI
// keys), since a registry list policy has no per-source split. Group Policy
// refreshes may rewrite the policy key if a GPO also sets this policy.
const markerKey = `HKLM\SOFTWARE\distrust\chromium`

// regStore is HKLM\<RegKey>\CADistrustedCertificates (values "1".."n").
// It uses the registry API directly: the values are whole certificates, far
// beyond what fits on a reg.exe command line.
type regStore struct{ key string }

func newStore(b *Browser) store {
	if b.RegKey == "" {
		return nil
	}
	return &regStore{key: `HKLM\` + b.RegKey}
}

func (r *regStore) listKey() string    { return r.key + `\` + PolicyKey }
func (r *regStore) ID() string         { return strings.ToLower(r.key) }
func (r *regStore) Path() string       { return r.listKey() }
func (r *regStore) markerName() string { return strings.ReplaceAll(r.key, `\`, "_") }

func (r *regStore) Exists() bool {
	k, err := openKey(r.key, syscall.KEY_READ)
	if err != nil {
		return false
	}
	syscall.RegCloseKey(k)
	return true
}

func (r *regStore) Read() (effective, error) {
	var values, marker []string
	if k, err := openKey(r.listKey(), syscall.KEY_READ); err == nil {
		for i := 1; ; i++ {
			v, err := getStrings(k, strconv.Itoa(i))
			if err != nil || len(v) == 0 {
				break
			}
			values = append(values, v[0])
		}
		syscall.RegCloseKey(k)
	} else if !notFound(err) {
		return effective{}, err
	}
	haveMarker := false
	if k, err := openKey(markerKey, syscall.KEY_READ); err == nil {
		if m, err := getStrings(k, r.markerName()); err == nil {
			marker, haveMarker = m, true
		}
		syscall.RegCloseKey(k)
	}
	return splitOwned(values, marker, haveMarker, r.listKey()), nil
}

func (r *regStore) Write(values, ours []string) error {
	if err := setList(r.listKey(), values); err != nil {
		return err
	}
	k, err := createKey(markerKey)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	return setValue(k, r.markerName(), regMultiSZ, multiSZ(ownedKeys(ours)))
}

// Remove drops our values and marker, leaving keep (others' values).
func (r *regStore) Remove(keep []string) error {
	var err error
	if len(keep) == 0 {
		err = deleteKey(r.listKey())
	} else {
		err = setList(r.listKey(), keep)
	}
	if err != nil {
		return err
	}
	if k, err := openKey(markerKey, syscall.KEY_SET_VALUE); err == nil {
		defer syscall.RegCloseKey(k)
		if err := deleteValue(k, r.markerName()); err != nil && !notFound(err) {
			return err
		}
	}
	return nil
}

// setList makes key hold exactly values as "1".."n".
func setList(key string, values []string) error {
	k, err := createKey(key)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	for i, v := range values {
		data, err := syscall.UTF16FromString(v)
		if err != nil {
			return err
		}
		if err := setValue(k, strconv.Itoa(i+1), syscall.REG_SZ, data); err != nil {
			return err
		}
	}
	for i := len(values) + 1; ; i++ {
		if err := deleteValue(k, strconv.Itoa(i)); err != nil {
			if notFound(err) {
				return nil
			}
			return err
		}
	}
}

const regMultiSZ = 7 // REG_MULTI_SZ

// registry access always uses the 64-bit view, which browsers read.
const view = syscall.KEY_WOW64_64KEY

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegCreateKeyEx = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueEx  = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValue = advapi32.NewProc("RegDeleteValueW")
	procRegDeleteKeyEx = advapi32.NewProc("RegDeleteKeyExW")
)

func subKey(path string) (*uint16, error) {
	return syscall.UTF16PtrFromString(strings.TrimPrefix(path, `HKLM\`))
}

func notFound(err error) bool { return errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) }

func regErr(r uintptr) error {
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func openKey(path string, access uint32) (syscall.Handle, error) {
	p, err := subKey(path)
	if err != nil {
		return 0, err
	}
	var k syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, access|view, &k)
	return k, err
}

func createKey(path string) (syscall.Handle, error) {
	p, err := subKey(path)
	if err != nil {
		return 0, err
	}
	var k syscall.Handle
	r, _, _ := procRegCreateKeyEx.Call(uintptr(syscall.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(p)), 0, 0, 0,
		uintptr(syscall.KEY_READ|syscall.KEY_WRITE|view), 0, uintptr(unsafe.Pointer(&k)), 0)
	return k, regErr(r)
}

func deleteKey(path string) error {
	p, err := subKey(path)
	if err != nil {
		return err
	}
	r, _, _ := procRegDeleteKeyEx.Call(uintptr(syscall.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(p)), uintptr(view), 0)
	if err := regErr(r); err != nil && !notFound(err) {
		return err
	}
	return nil
}

func setValue(k syscall.Handle, name string, typ uint32, data []uint16) error {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, _ := procRegSetValueEx.Call(uintptr(k), uintptr(unsafe.Pointer(n)), 0, uintptr(typ),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	return regErr(r)
}

func deleteValue(k syscall.Handle, name string) error {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, _ := procRegDeleteValue.Call(uintptr(k), uintptr(unsafe.Pointer(n)))
	return regErr(r)
}

// getStrings reads a REG_SZ (one string) or REG_MULTI_SZ value.
func getStrings(k syscall.Handle, name string) ([]string, error) {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var typ, size uint32
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, nil, &size); err != nil {
		return nil, err
	}
	buf := make([]uint16, size/2+1)
	size = uint32(len(buf) * 2)
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return nil, err
	}
	return splitMultiSZ(buf[:size/2]), nil
}

// multiSZ encodes strings as REG_MULTI_SZ data (each NUL-terminated, plus a
// final NUL).
func multiSZ(ss []string) []uint16 {
	var out []uint16
	for _, s := range ss {
		u, _ := syscall.UTF16FromString(s)
		out = append(out, u...)
	}
	return append(out, 0)
}

func splitMultiSZ(u []uint16) []string {
	var out []string
	start := 0
	for i, c := range u {
		if c == 0 {
			if i > start {
				out = append(out, syscall.UTF16ToString(u[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(u) {
		out = append(out, syscall.UTF16ToString(u[start:]))
	}
	return out
}
