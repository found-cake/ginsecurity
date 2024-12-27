package config

import (
	"time"

	"github.com/found-cake/ginsecurity/enums/method"
)

type CorsConfig struct {
	IsAllowCredentials     bool
	IsAllowAllOrigin       bool
	AllowOrigins           []string
	AllowMethods           []method.Method
	AllowHeaders           []string
	ExposeHeaders          []string
	MaxAge                 time.Duration
}

func defaultCORSConfig() *CorsConfig {
	return &CorsConfig{
		IsAllowCredentials:     false,
		AllowMethods:           method.ALL,
		AllowHeaders:           []string{"Origin", "Content-Length", "Content-Type"},
		MaxAge:                 10 * time.Minute,
	}
}
