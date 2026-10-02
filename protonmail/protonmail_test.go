package protonmail

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newRateLimitedServer returns a client for a server which rejects the first
// limited requests with 429 and retryAfter, and the number of requests it got.
func newRateLimitedServer(t *testing.T, limited int, retryAfter string) (*Client, *int) {
	t.Helper()

	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.Body != nil {
			if b, _ := io.ReadAll(r.Body); r.Method == http.MethodPost && string(b) != "{\"A\":1}\n" {
				t.Errorf("request %v: got body %q", n, b)
			}
		}
		if n <= limited {
			w.Header().Set("Retry-After", retryAfter)
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"Code": 2028, "Error": "Too many recent API requests"}`)
			return
		}
		io.WriteString(w, `{"Code": 1000}`)
	}))
	t.Cleanup(srv.Close)

	return &Client{RootURL: srv.URL}, &n
}

func TestRateLimitRetry(t *testing.T) {
	c, n := newRateLimitedServer(t, maxRetries, "0")

	req, err := c.newJSONRequest(http.MethodPost, "/test", struct{ A int }{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.doJSON(req, nil); err != nil {
		t.Fatalf("expected the request to succeed after retrying, got %v", err)
	}
	if *n != maxRetries+1 {
		t.Errorf("got %v requests, want %v", *n, maxRetries+1)
	}
}

func TestRateLimitGiveUp(t *testing.T) {
	const body = "{\"A\":1}\n"
	for name, tc := range map[string]struct {
		limited    int
		retryAfter string
		body       io.Reader
		want       int
	}{
		"too many retries": {maxRetries + 1, "0", strings.NewReader(body), maxRetries + 1},
		"delay too long":   {1, "3600", strings.NewReader(body), 1},
		// The body can't be sent again
		"streamed body": {1, "0", io.MultiReader(strings.NewReader(body)), 1},
	} {
		t.Run(name, func(t *testing.T) {
			c, n := newRateLimitedServer(t, tc.limited, tc.retryAfter)

			req, err := c.newRequest(http.MethodPost, "/test", tc.body)
			if err != nil {
				t.Fatal(err)
			}
			err = c.doJSON(req, nil)
			if apiErr, ok := err.(*APIError); !ok || apiErr.Code != 2028 {
				t.Errorf("got error %v, want the rate limit error", err)
			}
			if *n != tc.want {
				t.Errorf("got %v requests, want %v", *n, tc.want)
			}
		})
	}
}

func TestRetryDelay(t *testing.T) {
	for _, tc := range []struct {
		status     int
		retryAfter string
		delay      time.Duration
		ok         bool
	}{
		{http.StatusTooManyRequests, "5", 5 * time.Second, true},
		{http.StatusServiceUnavailable, "", defaultRetryDelay, true},
		{http.StatusTooManyRequests, "soon", defaultRetryDelay, true},
		{http.StatusTooManyRequests, "3600", 0, false},
		{http.StatusInternalServerError, "5", 0, false},
	} {
		resp := &http.Response{StatusCode: tc.status, Header: make(http.Header)}
		if tc.retryAfter != "" {
			resp.Header.Set("Retry-After", tc.retryAfter)
		}
		delay, ok := retryDelay(resp)
		if delay != tc.delay || ok != tc.ok {
			t.Errorf("%v with Retry-After %q: got (%v, %v), want (%v, %v)", tc.status, tc.retryAfter, delay, ok, tc.delay, tc.ok)
		}
	}
}

func TestReAuth(t *testing.T) {
	for name, tc := range map[string]struct {
		unauthorized int
		wantErr      bool
		wantReAuth   int
	}{
		"expired token":      {1, false, 1},
		"still unauthorized": {2, true, 1},
	} {
		t.Run(name, func(t *testing.T) {
			n := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n++
				if n <= tc.unauthorized {
					w.WriteHeader(http.StatusUnauthorized)
					io.WriteString(w, `{"Code": 401, "Error": "Invalid access token"}`)
					return
				}
				if got := r.Header.Get("Authorization"); got != "Bearer new" {
					t.Errorf("got Authorization %q", got)
				}
				io.WriteString(w, `{"Code": 1000}`)
			}))
			defer srv.Close()

			c := &Client{RootURL: srv.URL, uid: "uid", accessToken: "old"}
			reAuth := 0
			c.ReAuth = func() error {
				reAuth++
				c.accessToken = "new"
				return nil
			}

			req, err := c.newJSONRequest(http.MethodPost, "/test", struct{ A int }{1})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.doJSON(req, nil); (err != nil) != tc.wantErr {
				t.Errorf("got error %v", err)
			}
			if reAuth != tc.wantReAuth {
				t.Errorf("re-authenticated %v times, want %v", reAuth, tc.wantReAuth)
			}
		})
	}
}
