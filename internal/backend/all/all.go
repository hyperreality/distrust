// Package all links in every backend available on the build platform.
// Platform-neutral backends are imported here; the "system" backend comes
// from the per-OS file.
package all

import (
	_ "distrust/internal/backend/chromium"
	_ "distrust/internal/backend/java"
	_ "distrust/internal/backend/nss"
	_ "distrust/internal/backend/pembundle"
)
