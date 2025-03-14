package ginsecurity_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/found-cake/ginsecurity"
	"github.com/found-cake/ginsecurity/config"
	"github.com/found-cake/ginsecurity/utils"
	h "github.com/found-cake/ginsecurity/utils/header"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const resp_msg = "bar"

func setupFooRouter(config *config.SecurityConfig) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.Use(ginsecurity.New(config))
	r.GET("/foo", func(c *gin.Context) {
		c.String(http.StatusOK, resp_msg)
	})
	return r
}

func requestFoo(conf *config.SecurityConfig) *httptest.ResponseRecorder {
	r := setupFooRouter(conf)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/foo", nil)
	r.ServeHTTP(w, req)

	return w
}

func TestNOConf(t *testing.T) {
	w := requestFoo(&config.SecurityConfig{})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, resp_msg, w.Body.String())
}

func TestWriteHeader(t *testing.T) {
	w := requestFoo(&config.SecurityConfig{
		STS:                config.DefaultSTSConfig(),
		IENoOpen:           true,
		NoStoreCache:       true,
		ContentTypeNosniff: true,
		FrameDeny:          true,
		BrowserXssFilter:   utils.XSS_BLOCK,
	})
	header := w.Header()

	assert.NotEmpty(t, header.Get(h.XDownloadOpotions))
	assert.NotEmpty(t, header.Get(h.CacheControl))
	assert.NotEmpty(t, header.Get(h.Pragma))
	assert.NotEmpty(t, header.Get(h.Expires))
	assert.NotEmpty(t, header.Get(h.XContentTypeOptions))
	assert.NotEmpty(t, header.Get(h.XFrameOptions))
	assert.NotEmpty(t, header.Get(h.StrictTransportSecurity))
}

func TestSSLRedirect(t *testing.T) {
	w := requestFoo(&config.SecurityConfig{
		SSLConfig: &config.SSLConfig{
			IsRedirect: true,
		},
	})

	assert.Equal(t, http.StatusMovedPermanently, w.Code)
}

func TestSSLRedirectOtherHost(t *testing.T) {
	const testHost = "gin-gonic.com"
	w := requestFoo(&config.SecurityConfig{
		SSLConfig: &config.SSLConfig{
			IsRedirect: true,
			Host:       testHost,
		},
	})
	unescpaeurl, _ := url.PathUnescape(w.Header().Get("Location"))
	url, _ := url.Parse(unescpaeurl)

	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	assert.Equal(t, testHost, url.Host)
}

func TestCorsAllowAll(t *testing.T) {
	//TODO
}
