package chromium

// Policy directories below were read from each vendor's shipped binary
// (strings over the executable), not taken from documentation.
var browsers = []Browser{
	{Name: "chrome", Bins: []string{"/opt/google/chrome/chrome"}, PolicyDir: "/etc/opt/chrome/policies", VersionIsChromium: true},
	{Name: "chrome-beta", Bins: []string{"/opt/google/chrome-beta/chrome"}, PolicyDir: "/etc/opt/chrome/policies", VersionIsChromium: true},
	{Name: "chrome-unstable", Bins: []string{"/opt/google/chrome-unstable/chrome"}, PolicyDir: "/etc/opt/chrome/policies", VersionIsChromium: true},
	{Name: "chromium", Bins: []string{"/usr/lib/chromium/chromium", "/usr/lib64/chromium-browser/chromium-browser", "/usr/lib/chromium-browser/chromium-browser"}, PolicyDir: "/etc/chromium/policies", VersionIsChromium: true},
	// Ubuntu's chromium (snap) and some derivatives.
	{Name: "chromium-browser", Bins: []string{"/snap/chromium/current/usr/lib/chromium-browser/chrome"}, PolicyDir: "/etc/chromium-browser/policies", VersionIsChromium: true},
	{Name: "edge", Bins: []string{"/opt/microsoft/msedge/msedge"}, PolicyDir: "/etc/opt/edge/policies", VersionIsChromium: true},
	{Name: "edge-beta", Bins: []string{"/opt/microsoft/msedge-beta/msedge"}, PolicyDir: "/etc/opt/edge/policies", VersionIsChromium: true},
	{Name: "edge-dev", Bins: []string{"/opt/microsoft/msedge-dev/msedge"}, PolicyDir: "/etc/opt/edge/policies", VersionIsChromium: true},
	// Brave's flatpak also reads the host's /etc/brave/policies.
	{Name: "brave", Bins: []string{"/opt/brave.com/brave/brave", "/opt/brave.com/brave-beta/brave", "/opt/brave.com/brave-nightly/brave"}, PolicyDir: "/etc/brave/policies", VersionIsChromium: true},
	{Name: "vivaldi", Bins: []string{"/opt/vivaldi/vivaldi-bin", "/opt/vivaldi-snapshot/vivaldi-bin"}, PolicyDir: "/etc/vivaldi/policies"},
	{Name: "opera", Bins: []string{"/usr/lib/x86_64-linux-gnu/opera/opera", "/usr/lib/x86_64-linux-gnu/opera-stable/opera", "/usr/lib/opera/opera", "/usr/lib64/opera/opera"}, PolicyDir: "/etc/opt/opera/policies"},
}

const unsupportedReason = ""
