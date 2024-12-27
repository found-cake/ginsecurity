package config

import "github.com/found-cake/ginsecurity/enums/xss"

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
		SSLConfig:          defaultSSLConfig(),
		STS:                defaultSTSConfig(),
		CorsConfig:         defaultCORSConfig(),
		CsrfConfig:         defaultCsrfConfig(),
		IENoOpen:           true,
		NoStoreCache:       true,
		ContentTypeNosniff: true,
		FrameDeny:          true,
		BrowserXssFilter:   string(xss.DISABLE),
	}
}
