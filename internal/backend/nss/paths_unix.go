//go:build linux || freebsd || openbsd || netbsd

package nss

var profileGlobs = []string{
	".mozilla/firefox/*",
	"snap/firefox/common/.mozilla/firefox/*",
	".var/app/org.mozilla.firefox/.mozilla/firefox/*",
	".thunderbird/*",
	"snap/thunderbird/common/.thunderbird/*",
	".var/app/org.mozilla.Thunderbird/.thunderbird/*",
	".librewolf/*",
	".var/app/io.gitlab.librewolf-community/.librewolf/*",
	".waterfox/*",
	".floorp/*",
	".pki/nssdb",
	"snap/chromium/current/.pki/nssdb",
	".var/app/org.chromium.Chromium/.pki/nssdb",
	".var/app/com.google.Chrome/.pki/nssdb",
}

var systemDBs = []string{"/etc/pki/nssdb"}

var toolDirs = []string{"/usr/bin", "/usr/local/bin"}

var ckbiGlobs = []string{
	"/usr/lib/*-linux-gnu/libnssckbi.so",
	"/usr/lib64/libnssckbi.so",
	"/usr/lib/libnssckbi.so",
	"/usr/lib*/nss/libnssckbi.so",
	"/usr/lib/*/nss/libnssckbi.so",
	"/usr/lib*/firefox*/libnssckbi.so",
	"/usr/local/lib/libnssckbi.so",
	"/usr/local/lib/nss/libnssckbi.so",
}
