package config

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type CsrfConfig struct {
	SessionGetter  func(c *gin.Context) sessions.Session
	TokenGenerator func() string
	TokenGetter    func(c *gin.Context) string
	IgnoreMethods  []string
	IgnorePath     []string
}

func DefaultCsrfConfig() *CsrfConfig {
	return &CsrfConfig{
		SessionGetter: func(c *gin.Context) sessions.Session {
			return sessions.Default(c)
		},
		TokenGenerator: func() string {
			for i := 0; i < 3; i++ {
				uuid, err := uuid.NewRandom()
				if err == nil {
					return uuid.String()
				}
			}
			return "00000000-0000-0000-0000-000000000000"
		},
		TokenGetter: func(c *gin.Context) string {
			r := c.Request

			token := ""

			if token = r.FormValue("_csrf"); len(token) > 0 {
				return token
			} else if token = r.URL.Query().Get("_csrf"); len(token) > 0 {
				return token
			} else if token = r.Header.Get("X-CSRF-TOKEN"); len(token) > 0 {
				return token
			} else if token = r.Header.Get("X-XSRF-TOKEN"); len(token) > 0 {
				return token
			}

			return token
		},
		IgnoreMethods: []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodOptions,
		},
	}
}
