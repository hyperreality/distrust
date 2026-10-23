//go:build !linux && !windows

package chromium

// macOS honours Chromium policies only from managed preferences, which are
// owned by MDM / configuration profiles; writing them directly is overwritten
// on the next sync. Not supported yet.
var browsers []Browser

const unsupportedReason = "on macOS deploy " + PolicyKey + " with a configuration profile (MDM); not managed by distrust yet"
