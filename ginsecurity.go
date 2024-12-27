package ginsecurity

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/ginsecurity/config"
	"github.com/gin-gonic/gin"
)

type ginsecurity struct {
	sslConfig    *config.SSLConfig
	corsConfig   *config.CorsConfig
	csrfConfig   *config.CsrfConfig
	noCacheStore bool
	fixedHeaders http.Header
}

func newSecurity(config *config.SecurityConfig) *ginsecurity {
	fh := make(http.Header)
	if config.IENoOpen {
		fh.Set("X-Download-Options", "noopen")
	}
	if config.NoStoreCache {
		fh.Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
		fh.Set("Pragma", "no-cache")
		fh.Set("Expires", "0")
	}
	if config.ContentTypeNosniff {
		fh.Set("X-Content-Type-Options", "nosniff")
	}
	if config.FrameDeny {
		fh.Set("X-Frame-Options", "DENY")
	} else if len(config.CustomFrameOptionsValue) > 0 {
		fh.Set("X-Frame-Options", config.CustomFrameOptionsValue)
	}
	if len(config.BrowserXssFilter) > 0 {
		fh.Set("X-XSS-Protection", config.BrowserXssFilter)
	}
	if config.STS != nil {
		if value := config.STS.Value(); len(value) > 0 {
			fh.Set("Strict-Transport-Security", value)
		}
	}

	gs := &ginsecurity{
		sslConfig:    config.SSLConfig,
		corsConfig:   config.CorsConfig,
		csrfConfig:   config.CsrfConfig,
		noCacheStore: config.NoStoreCache,
		fixedHeaders: fh,
	}
	return gs
}

func (gs *ginsecurity) writeHeader(c *gin.Context) {
	header := c.Writer.Header()
	for k, v := range gs.fixedHeaders {
		header[k] = v
	}
}

// ssl
func (gs *ginsecurity) isSSLReq(req *http.Request) bool {
	if strings.EqualFold(req.URL.Scheme, "https") || req.TLS != nil {
		return true
	}
	for k, v := range gs.sslConfig.ProxyHeaders {
		hv, ok := req.Header[k]

		if !ok {
			continue
		}

		if strings.EqualFold(hv[0], v) {
			return true
		}
	}
	return false
}

func (gs *ginsecurity) checkSSL(c *gin.Context) bool {
	if !gs.sslConfig.IsRedirect {
		return true
	}

	req := c.Request
	if gs.isSSLReq(req) {
		return true
	}

	url := req.URL
	url.Scheme = "https"

	if len(gs.sslConfig.Host) > 0 {
		url.Host = gs.sslConfig.Host
	} else {
		url.Host = req.Host
	}

	c.Redirect(http.StatusMovedPermanently, url.String())
	c.Abort()
	return false
}

// cors
func (gs *ginsecurity) checkOrigin(origin string) bool {
	if gs.corsConfig.IsAllowAllOrigin {
		return true
	}
	for _, o := range gs.corsConfig.AllowOrigins {
		if o == origin {
			return true
		}
	}
	return false
}

func (gs *ginsecurity) checkCORS(c *gin.Context) bool {
	conf := gs.corsConfig
	origin := c.Request.Header.Get("Origin")
	if len(origin) == 0 {
		return true
	}
	// Same Origin
	host := c.Request.Host
	if origin == "http://"+host || origin == "https://"+host {
		return true
	}

	if !gs.checkOrigin(origin) {
		c.AbortWithStatus(http.StatusForbidden)
		return false
	}

	header := c.Writer.Header()
	if c.Request.Method == http.MethodOptions {
		if !conf.IsAllowAllOrigin && conf.IsAllowCredentials {
			header.Set("Access-Control-Allow-Credentials", "true")
		}
		if len(conf.AllowMethods) > 0 {
			allowMethods := normalize(conf.AllowHeaders, strings.ToUpper)
			header.Set("Access-Control-Allow-Methods", strings.Join(allowMethods, ","))
		}
		if len(conf.AllowHeaders) > 0 {
			allowHeaders := normalize(conf.AllowHeaders, http.CanonicalHeaderKey)
			header.Set("Access-Control-Allow-Headers", strings.Join(allowHeaders, ","))
		}
		if conf.MaxAge > time.Duration(0) {
			value := strconv.FormatInt(int64(conf.MaxAge/time.Second), 10)
			header.Set("Access-Control-Max-Age", value)
		}
		if conf.IsAllowAllOrigin {
			header.Set("Access-Control-Allow-Origin", "*")
		} else {
			header.Set("Access-Control-Allow-Origin", origin)
			if !gs.noCacheStore {
				header.Add("Vary", "Origin")
				header.Add("Vary", "Access-Control-Request-Method")
				header.Add("Vary", "Access-Control-Request-Headers")
			}
		}
	} else {
		if !conf.IsAllowAllOrigin && conf.IsAllowCredentials {
			header.Set("Access-Control-Allow-Credentials", "true")
		}
		if len(conf.ExposeHeaders) > 0 {
			exposeHeaders := normalize(conf.ExposeHeaders, http.CanonicalHeaderKey)
			header.Set("Access-Control-Expose-Headers", strings.Join(exposeHeaders, ","))
		}
		if conf.IsAllowAllOrigin {
			header.Set("Access-Control-Allow-Origin", "*")
		} else {
			header.Set("Access-Control-Allow-Origin", origin)
			if !gs.noCacheStore {
				header.Set("Vary", "Origin")
			}
		}
	}

	return true
}

//TODO CSRF

func (gs *ginsecurity) applyToContext(c *gin.Context) {
	gs.writeHeader(c)
	if gs.sslConfig != nil && !gs.checkSSL(c) {
		return
	}
	if gs.corsConfig != nil && !gs.checkCORS(c) {
		return
	}
}

func New(config *config.SecurityConfig) gin.HandlerFunc {
	gs := newSecurity(config)
	return func(c *gin.Context) {
		gs.applyToContext(c)
	}
}
