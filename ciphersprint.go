package ciphersprint

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/syntaqx/ciphersprint/pkg/challenge"
)

const (
	defaultBaseURL = "https://ciphersprint.pulley.com/"
)

type HTTPError struct {
	Code  int
	Error string
}

type Client struct {
	BaseURL    *url.URL
	httpClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	c := &Client{httpClient: httpClient}
	c.initialize()
	return c
}

func (c *Client) initialize() {
	if c.BaseURL == nil {
		c.BaseURL, _ = url.Parse(defaultBaseURL)
	}
}

func (c *Client) GetChallenge(url string) (*challenge.ChallengeResponse, error) {
	u, err := c.BaseURL.Parse(url)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var challenge challenge.ChallengeResponse
	if err := json.Unmarshal(body, &challenge); err != nil {
		return nil, err
	}

	return &challenge, nil
}
