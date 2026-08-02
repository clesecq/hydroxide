package captcha

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// openURL asks the desktop environment to open a URL in the user's browser.
//
// It only ever receives the local http://127.0.0.1 URL, never one carrying a
// token or a credential.
func openURL(url string) error {
	var name string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		name = "rundll32"
		args = []string{"url.dll,FileProtocolHandler"}
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return fmt.Errorf("no graphical session detected; use -captcha-mode manual")
		}
		name = "xdg-open"
	}

	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%v not found: %v", name, err)
	}

	cmd := exec.Command(path, append(args, url)...)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Don't block on a browser that stays in the foreground.
	go cmd.Wait()
	return nil
}
