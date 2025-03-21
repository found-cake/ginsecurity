package config

import (
	"regexp"
	"time"

	"github.com/found-cake/ginsecurity/utils"
	"github.com/found-cake/ginsecurity/utils/header"
	"github.com/gin-gonic/gin"
)

type CorsConfig struct {
	IsAllowCredentials bool
	IsAllowAllOrigin   bool
	AllowOrigins       []string
	AllowRegexOrigins  []regexp.Regexp
	CustomAllowOrigin  func(*gin.Context, string) bool
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
