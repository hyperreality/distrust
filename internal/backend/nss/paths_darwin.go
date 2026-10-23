//go:build darwin

package nss

var profileGlobs = []string{
	"Library/Application Support/Firefox/Profiles/*",
	"Library/Thunderbird/Profiles/*",
	"Library/Application Support/librewolf/Profiles/*",
	".pki/nssdb",
}

var systemDBs []string

var toolDirs = []string{"/opt/homebrew/bin", "/usr/local/bin", "/opt/homebrew/opt/nss/bin", "/usr/local/opt/nss/bin"}

var ckbiGlobs = []string{
	"/opt/homebrew/lib/libnssckbi.dylib",
	"/opt/homebrew/opt/nss/lib/libnssckbi.dylib",
	"/usr/local/opt/nss/lib/libnssckbi.dylib",
	"/Applications/Firefox.app/Contents/MacOS/libnssckbi.dylib",
}
