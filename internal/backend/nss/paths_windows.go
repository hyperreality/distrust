//go:build windows

package nss

var profileGlobs = []string{
	`AppData\Roaming\Mozilla\Firefox\Profiles\*`,
	`AppData\Roaming\Thunderbird\Profiles\*`,
	`AppData\Roaming\librewolf\Profiles\*`,
}

var systemDBs []string

// certutil.exe on Windows is Microsoft's tool; NSS's must come from an NSS
// build, typically shipped next to Firefox or installed separately.
var toolDirs = []string{`C:\Program Files\NSS\bin`, `C:\Program Files\Mozilla Firefox`}

var ckbiGlobs = []string{
	`C:\Program Files\Mozilla Firefox\nssckbi.dll`,
	`C:\Program Files\NSS\lib\nssckbi.dll`,
}
