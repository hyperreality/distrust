package java

import "runtime"

var cacertsGlobs, jdkBinGlobs = func() ([]string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return []string{
				"/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts",
				"/Library/Java/JavaVirtualMachines/*/Contents/Home/jre/lib/security/cacerts",
				"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts",
				"/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home/lib/security/cacerts",
			}, []string{
				"/Library/Java/JavaVirtualMachines/*/Contents/Home/bin",
				"/opt/homebrew/opt/openjdk/bin",
			}
	case "windows":
		return []string{
				`C:\Program Files\Java\*\lib\security\cacerts`,
				`C:\Program Files\Java\*\jre\lib\security\cacerts`,
				`C:\Program Files\Eclipse Adoptium\*\lib\security\cacerts`,
				`C:\Program Files\Microsoft\jdk-*\lib\security\cacerts`,
				`C:\Program Files\Amazon Corretto\*\lib\security\cacerts`,
			}, []string{
				`C:\Program Files\Java\*\bin`,
				`C:\Program Files\Eclipse Adoptium\*\bin`,
				`C:\Program Files\Microsoft\jdk-*\bin`,
			}
	}
	return []string{
			"/etc/ssl/certs/java/cacerts",
			"/etc/pki/java/cacerts",
			"/etc/pki/ca-trust/extracted/java/cacerts",
			"/usr/lib/jvm/*/lib/security/cacerts",
			"/usr/lib/jvm/*/jre/lib/security/cacerts",
			"/usr/lib64/jvm/*/lib/security/cacerts",
			"/usr/java/*/lib/security/cacerts",
			"/opt/*/lib/security/cacerts",
			"/opt/*/jre/lib/security/cacerts",
		}, []string{
			"/usr/lib/jvm/*/bin",
			"/usr/java/*/bin",
		}
}()
