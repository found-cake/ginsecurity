package ginsecurity_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/found-cake/ginsecurity"
	"github.com/found-cake/ginsecurity/config"
	"github.com/found-cake/ginsecurity/utils"
	h "github.com/found-cake/ginsecurity/utils/header"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const resp_msg = "bar"

func setupRouter(config *config.SecurityConfig) *gin.Engine {
	r := gin.Default()
	r.Use(ginsecurity.New(config))
	r.GET("/foo", func(c *gin.Context) {
		c.String(http.StatusOK, resp_msg)
	})
	return r
}

func TestNOConf(t *testing.T) {
	r := setupRouter(&config.SecurityConfig{})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, resp_msg, w.Body.String())
}

func TestWriteHeader(t *testing.T) {
	r := setupRouter(&config.SecurityConfig{
		STS:                config.DefaultSTSConfig(),
		IENoOpen:           true,
		NoStoreCache:       true,
		ContentTypeNosniff: true,
		FrameDeny:          true,
		BrowserXssFilter:   utils.XSS_BLOCK,
	})
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)
	r.ServeHTTP(w, req)

	header := w.Header()
	assert.NotEmpty(t, header.Get(h.StrictTransportSecurity))
}
