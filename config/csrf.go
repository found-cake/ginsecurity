package config

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CsrfConfig struct {
	SessionGetter  func(c *gin.Context) sessions.Session
	TokenGenerator func() (string, error)
	TokenGetter    func(c *gin.Context) string
	IgnoreMethods  []string
	IgnorePath     []string
}

func defaultCsrfConfig() *CsrfConfig {
	return &CsrfConfig{
		SessionGetter: func(c *gin.Context) sessions.Session {
			return sessions.Default(c)
		},
		TokenGenerator: func() (string, error) {
			if uuid, err := uuid.NewRandom(); err == nil {
				return uuid.String(), nil
			} else {
				return "", err
			}
		},
		TokenGetter: func(c *gin.Context) string {
			r := c.Request

			if token := r.FormValue("_csrf"); len(token) > 0 {
				return token
			} else if token := r.URL.Query().Get("_csrf"); len(token) > 0 {
				return token
			} else if token := r.Header.Get("X-CSRF-TOKEN"); len(token) > 0 {
				return token
			} else if token := r.Header.Get("X-XSRF-TOKEN"); len(token) > 0 {
				return token
			}

			return ""
		},
		IgnoreMethods: []string{},
	}
}
