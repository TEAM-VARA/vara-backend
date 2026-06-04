package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Client : CISA Known Exploited Vulnerabilities 클라이언트
type Client struct {
	url      string
	http     *http.Client
	mu       sync.RWMutex
	cache    map[string]Entry
	loadedAt time.Time
	cacheTTL time.Duration
}

type Entry struct {
	CVEID         string `json:"cveID"`
	VendorProject string `json:"vendorProject"`
	Product       string `json:"product"`
	VulnName      string `json:"vulnerabilityName"`
	DateAdded     string `json:"dateAdded"`
	DueDate       string `json:"dueDate"`
	ShortDesc     string `json:"shortDescription"`
}

type feed struct {
	Vulnerabilities []Entry `json:"vulnerabilities"`
}

func NewClient() *Client {
	return &Client{
		url:      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		http:     &http.Client{Timeout: 30 * time.Second},
		cache:    make(map[string]Entry),
		cacheTTL: 24 * time.Hour,
	}
}

func (c *Client) IsListed(ctx context.Context, cveID string) (*Entry, error) {
	if err := c.ensureLoaded(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.cache[cveID]; ok {
		return &entry, nil
	}
	return nil, nil
}

func (c *Client) ensureLoaded(ctx context.Context) error {
	c.mu.RLock()
	stale := time.Since(c.loadedAt) > c.cacheTTL || len(c.cache) == 0
	c.mu.RUnlock()
	if !stale {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kev fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("kev status %d", resp.StatusCode)
	}

	var f feed
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil {
		return fmt.Errorf("kev decode: %w", err)
	}

	c.mu.Lock()
	c.cache = make(map[string]Entry, len(f.Vulnerabilities))
	for _, v := range f.Vulnerabilities {
		c.cache[v.CVEID] = v
	}
	c.loadedAt = time.Now()
	c.mu.Unlock()

	return nil
}
