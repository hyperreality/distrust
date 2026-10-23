package chromium

// Policy registry keys under HKLM. Vivaldi and Opera publish no Windows
// policy key documentation, so they are not listed.
var browsers = []Browser{
	{Name: "chrome", Bins: []string{`C:\Program Files\Google\Chrome\Application\chrome.exe`, `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`}, RegKey: `SOFTWARE\Policies\Google\Chrome`},
	{Name: "chromium", Bins: []string{`C:\Program Files\Chromium\Application\chrome.exe`}, RegKey: `SOFTWARE\Policies\Chromium`},
	{Name: "edge", Bins: []string{`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, `C:\Program Files\Microsoft\Edge\Application\msedge.exe`}, RegKey: `SOFTWARE\Policies\Microsoft\Edge`},
	{Name: "brave", Bins: []string{`C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe`}, RegKey: `SOFTWARE\Policies\BraveSoftware\Brave`},
}

const unsupportedReason = ""
