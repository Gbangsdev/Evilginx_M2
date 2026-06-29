//go:build !googlebypass

package core

import "fmt"

// PatchGoogleBotGuardToken is a no-op unless built with -tags googlebypass.
func PatchGoogleBotGuardToken(body []byte) ([]byte, error) {
	return body, fmt.Errorf("google BotGuard bypass requires building with -tags googlebypass and Chrome on port 9222")
}
