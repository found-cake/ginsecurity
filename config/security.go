package config

import "github.com/found-cake/ginsecurity/utils"

type SecurityConfig struct {
	*SSLConfig
	*CorsConfig
	*CsrfConfig
	STS *StrictTransportSecurityConfig

	IENoOpen                bool
	NoStoreCache            bool
	ContentTypeNosniff      bool
	FrameDeny               bool
	CustomFrameOptionsValue string
	BrowserXssFilter        string
}

func Default() *SecurityConfig {
	return &SecurityConfig{
		SSLConfig:          DefaultSSLConfig(),
		STS:                DefaultSTSConfig(),
		CorsConfig:         DefaultCORSConfig(),
		CsrfConfig:         DefaultCsrfConfig(),
		IENoOpen:           true,
		NoStoreCache:       true,
		ContentTypeNosniff: true,
		FrameDeny:          true,
		BrowserXssFilter:   string(utils.XSS_DISABLE),
	}
}
