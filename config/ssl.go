package config

type SSLConfig struct {
	IsRedirect   bool
	ProxyHeaders map[string]string
	Host         string
}

func DefaultSSLConfig() *SSLConfig {
	return &SSLConfig{
		IsRedirect: false,
	}
}
