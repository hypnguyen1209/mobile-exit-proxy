package main

import (
	"os"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/tailscale/hujson"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type ProxyBackend struct {
	Addr     string `json:"addr"`
	Alias    string `json:"alias"`
	Username string `json:"username"`
	Password string `json:"password"`
	// Health check: if true, periodically verify this proxy is reachable.
	HealthCheck bool `json:"health_check"`
}

type Config struct {
	// Tailscale settings
	Hostname string `json:"hostname"`
	AuthKey  string `json:"authkey"`
	StateDir string `json:"state_dir"`

	// Proxy backends (multiple Burp instances, with rotation/failover)
	Proxies []*ProxyBackend `json:"proxies"`

	// DNS upstream servers
	DNS []string `json:"dns"`

	// Performance tuning
	DialTimeout    Duration `json:"dial_timeout"`
	BufferSize     int      `json:"buffer_size"`      // bytes for io.Copy buffer (default 32KB)
	MaxIdleTime    Duration `json:"max_idle_time"`     // close idle connections after this
	HealthInterval Duration `json:"health_interval"`   // how often to check proxy health

	// Passthrough: domains/suffixes that bypass Burp and connect directly.
	// Use this for apps with SSL pinning that break through Burp.
	// Supports exact match ("api.example.com") and suffix match (".example.com").
	Passthrough []string `json:"passthrough"`

	// InterceptOnly: if non-empty, ONLY these domains go through Burp.
	// Everything else connects directly. Opposite of Passthrough.
	InterceptOnly []string `json:"intercept_only"`

	// Web control panel
	WebListen string `json:"web_listen"` // e.g. ":8080" on tsnet

	Verbose bool `json:"verbose"`
}

func DefaultConfig() *Config {
	return &Config{
		Hostname: "mobile-exit-proxy",
		Proxies: []*ProxyBackend{
			{Addr: "127.0.0.1:8083", Alias: "burpsuite"},
		},
		DNS:            []string{"8.8.8.8:53", "1.1.1.1:53"},
		DialTimeout:    Duration(10 * time.Second),
		BufferSize:     32 * 1024,
		MaxIdleTime:    Duration(5 * time.Minute),
		HealthInterval: Duration(30 * time.Second),
		WebListen:      ":8080",
		Verbose:        false,
	}
}

func ParseConfig(f string) (*Config, error) {
	config := DefaultConfig()
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}

	data, err := hujson.Standardize(b)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// Duration embeds time.Duration and makes it more JSON-friendly.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	val, err := time.ParseDuration(str)
	*d = Duration(val)
	return err
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}
