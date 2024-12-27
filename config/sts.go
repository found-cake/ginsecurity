package config

import (
	"fmt"
)

type StrictTransportSecurityConfig struct {
	Seconds           int64
	IncludeSubdomains bool
	Preload           bool
}

func (sts *StrictTransportSecurityConfig) Value() string {
	if sts.Seconds == 0 {
		return ""
	}
	v := fmt.Sprintf("max-age=%d", sts.Seconds)
	if sts.IncludeSubdomains {
		v += "; includeSubDomains"
	}
	if sts.Preload {
		v += "; preload"
	}
	return v
}

func defaultSTSConfig() *StrictTransportSecurityConfig {
	return &StrictTransportSecurityConfig{
		Seconds:           31536000,
		IncludeSubdomains: true,
		Preload:           false,
	}
}
