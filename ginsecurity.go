package ginsecurity

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/found-cake/ginsecurity/config"
	"github.com/found-cake/ginsecurity/utils"
	h "github.com/found-cake/ginsecurity/utils/header"
	"github.com/gin-gonic/gin"
)

type GinSecurity struct {
	sslConfig    *config.SSLConfig
	corsConfig   *config.CorsConfig
	csrfConfig   *config.CsrfConfig
	noCacheStore bool
	fixedHeaders http.Header
}

func newSecurity(config *config.SecurityConfig) *GinSecurity {
	fh := make(http.Header)
	if config.IENoOpen {
		fh.Set(h.XDownloadOpotions, "noopen")
	}
	if config.NoStoreCache {
		fh.Set(h.CacheControl, "no-cache, no-store, max-age=0, must-revalidate")
		fh.Set(h.Pragma, "no-cache")
		fh.Set(h.Expires, "0")
	}
	if config.ContentTypeNosniff {
		fh.Set(h.XContentTypeOptions, "nosniff")
	}
	if config.FrameDeny {
		fh.Set(h.XFrameOptions, "DENY")
	} else if len(config.CustomFrameOptionsValue) > 0 {
		fh.Set(h.XFrameOptions, config.CustomFrameOptionsValue)
	}
	if len(config.BrowserXssFilter) > 0 {
		fh.Set(h.XSSProtection, config.BrowserXssFilter)
	}
	if config.STS != nil {
		if value := config.STS.Value(); len(value) > 0 {
			fh.Set(h.StrictTransportSecurity, value)
		}
	}

	gs := &GinSecurity{
		sslConfig:    config.SSLConfig,
		corsConfig:   config.CorsConfig,
		csrfConfig:   config.CsrfConfig,
		noCacheStore: config.NoStoreCache,
		fixedHeaders: fh,
	}
	return gs
}

func (gs *GinSecurity) writeHeader(c *gin.Context) {
	header := c.Writer.Header()
	for k, v := range gs.fixedHeaders {
		header[k] = v
	}
}

// ssl
func (gs *GinSecurity) isSSLReq(req *http.Request) bool {
	if strings.EqualFold(req.URL.Scheme, utils.HTTPS_SCHEME) || req.TLS != nil {
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

func (gs *GinSecurity) checkSSL(c *gin.Context) bool {
	if !gs.sslConfig.IsRedirect {
		return true
	}

	req := c.Request
	if gs.isSSLReq(req) {
		return true
	}

	url := req.URL
	url.Scheme = utils.HTTPS_SCHEME

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
func (gs *GinSecurity) checkOrigin(origin string) bool {
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

func (gs *GinSecurity) checkCORS(c *gin.Context) bool {
	conf := gs.corsConfig
	origin := c.Request.Header.Get(h.Origin)
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
			header.Set(h.AccessControlAllowCredentials, "true")
		}
		if len(conf.AllowMethods) > 0 {
			allowMethods := utils.Normalize(conf.AllowHeaders, strings.ToUpper)
			header.Set(h.AccessControlAllowMethod, strings.Join(allowMethods, ","))
		}
		if len(conf.AllowHeaders) > 0 {
			allowHeaders := utils.Normalize(conf.AllowHeaders, http.CanonicalHeaderKey)
			header.Set(h.AccessControlAllowHeaders, strings.Join(allowHeaders, ","))
		}
		if conf.MaxAge > time.Duration(0) {
			value := strconv.FormatInt(int64(conf.MaxAge/time.Second), 10)
			header.Set(h.AccessControlMaxAge, value)
		}
		if conf.IsAllowAllOrigin {
			header.Set(h.AccessControlAllowOrigin, "*")
		} else {
			header.Set(h.AccessControlAllowOrigin, origin)
			if !gs.noCacheStore {
				header.Add(h.Vary, h.Origin)
				header.Add(h.Vary, h.AccessControlRequestMethod)
				header.Add(h.Vary, h.AccessControlRequestHeaders)
			}
		}
	} else {
		if !conf.IsAllowAllOrigin && conf.IsAllowCredentials {
			header.Set(h.AccessControlAllowCredentials, "true")
		}
		if len(conf.ExposeHeaders) > 0 {
			exposeHeaders := utils.Normalize(conf.ExposeHeaders, http.CanonicalHeaderKey)
			header.Set(h.AccessControlExposeHeaders, strings.Join(exposeHeaders, ","))
		}
		if conf.IsAllowAllOrigin {
			header.Set(h.AccessControlAllowOrigin, "*")
		} else {
			header.Set(h.AccessControlAllowOrigin, origin)
			if !gs.noCacheStore {
				header.Set(h.Vary, h.Origin)
			}
		}
	}

	return true
}

func (gs *GinSecurity) checkCSRF(c *gin.Context) bool {
	conf := gs.csrfConfig
	if utils.InArray(conf.IgnoreMethods, c.Request.Method) {
		return true
	}
	if utils.InArray(conf.IgnorePath, c.Request.URL.Path) {
		return true
	}

	session := conf.SessionGetter(c)
	token, ok := session.Get(utils.CsrfToken).(string)
	if !ok || len(token) == 0 || conf.TokenGetter(c) != token {
		c.AbortWithStatus(http.StatusBadRequest)
		return false
	}

	return true
}

func (gs *GinSecurity) getCsrfToken(c *gin.Context) (string, error) {
	if gs.csrfConfig == nil {
		return "", errors.New("CsrfConfig must not be null")
	}
	conf := gs.csrfConfig
	session := conf.SessionGetter(c)
	if token, err := conf.TokenGenerator(); err != nil {
		return token, err
	} else {
		session.Set(utils.CsrfToken, token)
		session.Save()
		return token, err
	}
}

func (gs *GinSecurity) applyToContext(c *gin.Context) {
	gs.writeHeader(c)
	if gs.sslConfig != nil && !gs.checkSSL(c) {
		return
	}
	if gs.corsConfig != nil && !gs.checkCORS(c) {
		return
	}
	if gs.csrfConfig != nil && !gs.checkCSRF(c) {
		return
	}
}

var GetCSRFToken func(c *gin.Context) (string, error)

func New(config *config.SecurityConfig) gin.HandlerFunc {
	gs := newSecurity(config)
	GetCSRFToken = gs.getCsrfToken
	return func(c *gin.Context) {
		gs.applyToContext(c)
	}
}
