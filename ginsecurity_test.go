package ginsecurity_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/found-cake/ginsecurity"
	"github.com/found-cake/ginsecurity/config"
	"github.com/found-cake/ginsecurity/utils"
	"github.com/found-cake/ginsecurity/utils/csp"
	h "github.com/found-cake/ginsecurity/utils/header"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// utils test
var exmaple_list = []string{"a", "b", "c"}

func TestStringsChange(t *testing.T) {
	b := utils.StringsChange(exmaple_list, strings.ToUpper)
	assert.Equal(t, b, []string{"A", "B", "C"})
}

func TestInArray(t *testing.T) {
	assert.True(t, utils.InArray(exmaple_list, "a"))
	assert.False(t, utils.InArray(exmaple_list, "d"))
}

// middleware test
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

func requestFooOrigin(r *gin.Engine, origin string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/foo", nil)
	req.Header.Set(h.Origin, origin)
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

func TestSSLNoRedirect(t *testing.T) {
	w := requestFoo(&config.SecurityConfig{
		SSLConfig: &config.SSLConfig{
			IsRedirect: false,
		},
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, resp_msg, w.Body.String())
}

func TestSSLRedirectOtherHost(t *testing.T) {
	testHost := "gin-gonic.com"
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

func TestCSPGenerateHeader(t *testing.T) {
	conf := config.NewCSPBuilder().
		SetDirective(csp.DefaultSrc, csp.Self, csp.Self).
		SetDirective(csp.ObjectSrc, csp.None).
		AddDirective(csp.ImgSrc, csp.Self, "gin-gonic.com").
		AddDirective(csp.ImgSrc, "*.google.com", "gin-gonic.com").
		AddDirective(csp.ConnectSrc, csp.Self)
	hValue := conf.GenerateHeader()

	assert.True(t, strings.Contains(hValue, csp.DefaultSrc))
	assert.True(t, strings.Contains(hValue, csp.ObjectSrc))
	assert.True(t, strings.Contains(hValue, csp.ImgSrc))
	assert.True(t, strings.Index(hValue, csp.ObjectSrc) > strings.Index(hValue, csp.ImgSrc))
	assert.False(t, strings.Index(hValue, csp.ConnectSrc) < strings.Index(hValue, csp.DefaultSrc))
	assert.Equal(t, 1, strings.Count(hValue, "gin-gonic.com"))
}

func TestCSP(t *testing.T) {
	conf := config.NewCSPBuilder().
		SetDirective(csp.DefaultSrc, csp.Self).
		SetDirective(csp.ObjectSrc, csp.None)
	w := requestFoo(&config.SecurityConfig{
		CSPConfig: conf,
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, conf.GenerateHeader(), w.Header().Get(h.ContentSecurityPolicy))
}

func TestCorsAllowAll(t *testing.T) {
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig: &config.CorsConfig{
			IsAllowAllOrigin:   true,
			IsAllowCredentials: false,
			AllowMethods:       utils.HTTP_METHOD_ALL,
			AllowHeaders:       []string{h.Origin, h.ContentLength, h.ContentType},
			MaxAge:             10 * time.Minute,
		},
	})

	for _, o := range []string{"https://gin-gonic.com", "https://go.dev", "https://www.google.com"} {
		w := requestFooOrigin(r, o)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, resp_msg, w.Body.String())
		assert.Equal(t, "*", w.Header().Get(h.AccessControlAllowOrigin))
	}
}

func TestCorsAllowOrigins(t *testing.T) {
	origin := "https://go.dev"
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig: &config.CorsConfig{
			IsAllowCredentials: false,
			AllowOrigins:       []string{origin},
			AllowMethods:       utils.HTTP_METHOD_ALL,
			AllowHeaders:       []string{h.Origin, h.ContentLength, h.ContentType},
			MaxAge:             10 * time.Minute,
		},
	})

	w := requestFooOrigin(r, "https://gin-gonic.com")
	assert.Equal(t, http.StatusForbidden, w.Code)

	w = requestFooOrigin(r, "https://go.dev")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, resp_msg, w.Body.String())
	assert.Equal(t, origin, w.Header().Get(h.AccessControlAllowOrigin))
	assert.True(t, utils.InArray(w.Header().Values(h.Vary), h.Origin))
}

func TestCorsNoCache(t *testing.T) {
	origin := "https://go.dev"
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig: &config.CorsConfig{
			IsAllowCredentials: false,
			AllowOrigins:       []string{origin},
			AllowMethods:       utils.HTTP_METHOD_ALL,
			AllowHeaders:       []string{h.Origin, h.ContentLength, h.ContentType},
			MaxAge:             10 * time.Minute,
		},
		NoStoreCache: true,
	})

	w := requestFooOrigin(r, origin)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, resp_msg, w.Body.String())
	assert.Equal(t, origin, w.Header().Get(h.AccessControlAllowOrigin))
	assert.Empty(t, w.Header().Values(h.Vary))
}

func TestCorsExposeHeader(t *testing.T) {
	origin := "https://go.dev"
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig: &config.CorsConfig{
			IsAllowCredentials: false,
			AllowOrigins:       []string{origin},
			AllowMethods:       utils.HTTP_METHOD_ALL,
			AllowHeaders:       []string{h.Origin, h.ContentLength, h.ContentType},
			MaxAge:             10 * time.Minute,
			ExposeHeaders:      []string{"Content-Encoding"},
		},
	})

	w := requestFooOrigin(r, origin)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, resp_msg, w.Body.String())
	assert.Equal(t, origin, w.Header().Get(h.AccessControlAllowOrigin))
	assert.Equal(t, "Content-Encoding", w.Header().Get(h.AccessControlExposeHeaders))
}

func TestCorsAllowRegexOrigins(t *testing.T) {
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig: &config.CorsConfig{
			IsAllowCredentials: false,
			AllowRegexOrigins:  []regexp.Regexp{*regexp.MustCompile(`^https:\/\/.*gin.*$`)},
			AllowMethods:       utils.HTTP_METHOD_ALL,
			AllowHeaders:       []string{h.Origin, h.ContentLength, h.ContentType},
			MaxAge:             10 * time.Minute,
		},
		NoStoreCache: true,
	})

	o := "https://gin-gonic.com"
	w := requestFooOrigin(r, o)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, resp_msg, w.Body.String())
	assert.Equal(t, o, w.Header().Get(h.AccessControlAllowOrigin))

	o = "https://go.dev"
	w = requestFooOrigin(r, o)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCorsCustomAllowOrigin(t *testing.T) {
	config := &config.SecurityConfig{
		CorsConfig: &config.CorsConfig{
			IsAllowCredentials: false,
			AllowOrigins:       []string{"https://go.dev"},
			CustomAllowOrigin: func(c *gin.Context, _ string) bool {
				return c.Request.URL.Path != "/foo"
			},
			AllowMethods: utils.HTTP_METHOD_ALL,
			AllowHeaders: []string{h.Origin, h.ContentLength, h.ContentType},
			MaxAge:       10 * time.Minute,
		},
		NoStoreCache: true,
	}

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.Use(ginsecurity.New(config))
	r.GET("/foo", func(c *gin.Context) {
		c.String(http.StatusOK, resp_msg)
	})
	r.POST("/bar", func(c *gin.Context) {
		c.String(http.StatusOK, "baz")
	})

	origin := "https://gin-gonic.com"

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/foo", nil)
	req.Header.Set(h.Origin, origin)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/bar", nil)
	req.Header.Set(h.Origin, origin)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "baz", w.Body.String())
	assert.Equal(t, origin, w.Header().Get(h.AccessControlAllowOrigin))

	origin = "https://go.dev"
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/foo", nil)
	req.Header.Set(h.Origin, origin)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, resp_msg, w.Body.String())
	assert.Equal(t, origin, w.Header().Get(h.AccessControlAllowOrigin))
}

func TestPreflightAllowAll(t *testing.T) {
	origin := "https://gin-gonic.com"

	conf := config.DefaultCORSConfig()
	conf.IsAllowAllOrigin = true
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig: conf,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(h.Origin, origin)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, strings.Join(utils.StringsChange(utils.HTTP_METHOD_ALL, strings.ToUpper), ","), w.Header().Get(h.AccessControlAllowMethod))
	assert.Equal(t, strings.Join(utils.StringsChange([]string{h.Origin, h.ContentLength, h.ContentType}, http.CanonicalHeaderKey), ","), w.Header().Get(h.AccessControlAllowHeaders))
	assert.Equal(t, "600", w.Header().Get(h.AccessControlMaxAge))
	assert.Equal(t, "*", w.Header().Get(h.AccessControlAllowOrigin))
}

func TestPreflightAllowOrigins(t *testing.T) {
	origin := "https://gin-gonic.com"

	conf := config.DefaultCORSConfig()
	conf.AllowOrigins = []string{"https://gin-gonic.com"}
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig: conf,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(h.Origin, origin)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, strings.Join(utils.StringsChange(utils.HTTP_METHOD_ALL, strings.ToUpper), ","), w.Header().Get(h.AccessControlAllowMethod))
	assert.Equal(t, strings.Join(utils.StringsChange([]string{h.Origin, h.ContentLength, h.ContentType}, http.CanonicalHeaderKey), ","), w.Header().Get(h.AccessControlAllowHeaders))
	assert.Equal(t, "600", w.Header().Get(h.AccessControlMaxAge))
	assert.Equal(t, origin, w.Header().Get(h.AccessControlAllowOrigin))
	assert.True(t, utils.InArray(w.Header().Values(h.Vary), h.Origin))
	assert.True(t, utils.InArray(w.Header().Values(h.Vary), h.AccessControlRequestMethod))
	assert.True(t, utils.InArray(w.Header().Values(h.Vary), h.AccessControlRequestHeaders))
}

func TestPreflightNoCache(t *testing.T) {
	origin := "https://gin-gonic.com"

	conf := config.DefaultCORSConfig()
	conf.AllowOrigins = []string{"https://gin-gonic.com"}
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig:   conf,
		NoStoreCache: true,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(h.Origin, origin)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, strings.Join(utils.StringsChange(utils.HTTP_METHOD_ALL, strings.ToUpper), ","), w.Header().Get(h.AccessControlAllowMethod))
	assert.Equal(t, strings.Join(utils.StringsChange([]string{h.Origin, h.ContentLength, h.ContentType}, http.CanonicalHeaderKey), ","), w.Header().Get(h.AccessControlAllowHeaders))
	assert.Equal(t, "600", w.Header().Get(h.AccessControlMaxAge))
	assert.Equal(t, origin, w.Header().Get(h.AccessControlAllowOrigin))
	assert.Empty(t, w.Header().Values(h.Vary))
}

func TestPrefileghtCredentials(t *testing.T) {
	origin := "https://gin-gonic.com"

	conf := config.DefaultCORSConfig()
	conf.AllowOrigins = []string{"https://gin-gonic.com"}
	conf.IsAllowCredentials = true
	r := setupFooRouter(&config.SecurityConfig{
		CorsConfig: conf,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set(h.Origin, origin)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "true", w.Header().Get(h.AccessControlAllowCredentials))
	assert.Equal(t, strings.Join(utils.StringsChange(utils.HTTP_METHOD_ALL, strings.ToUpper), ","), w.Header().Get(h.AccessControlAllowMethod))
	assert.Equal(t, strings.Join(utils.StringsChange([]string{h.Origin, h.ContentLength, h.ContentType}, http.CanonicalHeaderKey), ","), w.Header().Get(h.AccessControlAllowHeaders))
	assert.Equal(t, "600", w.Header().Get(h.AccessControlMaxAge))
	assert.Equal(t, origin, w.Header().Get(h.AccessControlAllowOrigin))
	assert.True(t, utils.InArray(w.Header().Values(h.Vary), h.Origin))
	assert.True(t, utils.InArray(w.Header().Values(h.Vary), h.AccessControlRequestMethod))
	assert.True(t, utils.InArray(w.Header().Values(h.Vary), h.AccessControlRequestHeaders))
}

// TODO: CSRF TEST
// The PR(https://github.com/gin-contrib/sessions/pull/144) is merged, I'll continue writing the test code.
