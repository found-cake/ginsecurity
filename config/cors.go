package config

import (
	"regexp"
	"time"

	"github.com/found-cake/ginsecurity/utils"
	"github.com/found-cake/ginsecurity/utils/header"
)

type CorsConfig struct {
	IsAllowCredentials bool
	IsAllowAllOrigin   bool
	AllowOrigins       []string
	AllowRegexOrigins  []regexp.Regexp
	AllowMethods       []string
	AllowHeaders       []string
	ExposeHeaders      []string
	MaxAge             time.Duration
}

func DefaultCORSConfig() *CorsConfig {
	return &CorsConfig{
		IsAllowCredentials: false,
		AllowMethods:       utils.HTTP_METHOD_ALL,
		AllowHeaders:       []string{header.Origin, header.ContentLength, header.ContentType},
		MaxAge:             10 * time.Minute,
	}
}
