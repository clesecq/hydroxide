// Package protonmail implements a ProtonMail API client.
package protonmail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"log"
)

const Version = 3

const headerAPIVersion = "X-Pm-Apiversion"

type resp struct {
	Code int
	*RawAPIError
}

func (r *resp) Err() error {
	// Details alone doesn't make a response an error: only report one when the
	// API actually returned an error message.
	if err := r.RawAPIError; err != nil && err.Message != "" {
		return &APIError{
			Code:    r.Code,
			Message: err.Message,
			Details: err.Details,
		}
	}
	return nil
}

type maybeError interface {
	Err() error
}

type RawAPIError struct {
	Message string `json:"Error"`
	// Details holds request-specific error details, e.g. a human verification
	// challenge. Its contents vary from one endpoint to another.
	Details json.RawMessage `json:"Details,omitempty"`
}

type APIError struct {
	Code    int
	Message string
	Details json.RawMessage
}

func (err *APIError) Error() string {
	return fmt.Sprintf("[%v] %v", err.Code, err.Message)
}

type Timestamp int64

func NewTimestamp(t time.Time) Timestamp {
	return Timestamp(t.Unix())
}

func (t Timestamp) Time() time.Time {
	return time.Unix(int64(t), 0)
}

// Client is a ProtonMail API client.
type Client struct {
	RootURL    string
	AppVersion string
	Debug      bool

	HTTPClient *http.Client
	ReAuth     func() error

	uid         string
	accessToken string
	keyRing     openpgp.EntityList
}

func (c *Client) setRequestAuthorization(req *http.Request) {
	if c.uid != "" && c.accessToken != "" {
		req.Header.Set("X-Pm-Uid", c.uid)
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.RootURL+path, body)
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Printf(">> %v %v\n", req.Method, req.URL.Path)
	}

	req.Header.Set("X-Pm-Appversion", c.AppVersion)
	req.Header.Set(headerAPIVersion, strconv.Itoa(Version))
	c.setRequestAuthorization(req)
	return req, nil
}

func (c *Client) newJSONRequest(method, path string, body interface{}) (*http.Request, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, err
	}
	b := buf.Bytes()

	req, err := c.newRequest(method, path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	if c.Debug {
		log.Print(string(redactJSON(b)))
	}

	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) {
		return ioutil.NopCloser(bytes.NewReader(b)), nil
	}
	return req, nil
}

// Retry policy for rate-limited requests, matching the official clients.
const (
	maxRetries        = 3
	maxRetryDelay     = time.Minute
	defaultRetryDelay = 10 * time.Second
)

// retryDelay returns how long to wait before retrying a request which got
// resp, or false if it shouldn't be retried.
func retryDelay(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
		return 0, false
	}

	delay := defaultRetryDelay
	if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs >= 0 {
		delay = time.Duration(secs) * time.Second
	}
	if delay > maxRetryDelay {
		return 0, false
	}
	return delay, true
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "Ubuntu_20.04")
	req.Header.Set("x-pm-appversion", "Other")

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	canRetry := req.Body == nil || req.GetBody != nil
	reauthenticated := false
	rateLimited := 0
	for {
		resp, err := httpClient.Do(req)
		if err != nil || !canRetry {
			return resp, err
		}

		_, hasAuth := req.Header["Authorization"]
		if resp.StatusCode == http.StatusUnauthorized && hasAuth && c.ReAuth != nil && !reauthenticated {
			// The access token has expired
			resp.Body.Close()
			c.accessToken = ""
			if err := c.ReAuth(); err != nil {
				return resp, err
			}
			c.setRequestAuthorization(req) // Access token has changed
			reauthenticated = true
		} else if delay, ok := retryDelay(resp); ok && rateLimited < maxRetries {
			rateLimited++
			resp.Body.Close()
			log.Printf("%v %v: rate limited, retrying in %v", req.Method, req.URL.Path, delay)
			time.Sleep(delay)
		} else {
			return resp, nil
		}

		if req.Body != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = body
		}
	}
}

func (c *Client) doJSON(req *http.Request, respData interface{}) error {
	req.Header.Set("Accept", "application/json")

	if respData == nil {
		respData = new(resp)
	}

	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(respData); err != nil {
		return err
	}

	if c.Debug {
		log.Printf("<< %v %v", req.Method, req.URL.Path)
		log.Printf("%s", redactValueOf(respData))
	}

	if maybeError, ok := respData.(maybeError); ok {
		if err := maybeError.Err(); err != nil {
			log.Printf("request failed: %v %v: %v", req.Method, req.URL.String(), err)
			return err
		}
	}
	return nil
}
