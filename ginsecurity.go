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

type corsHeader struct {
	AllowMethods  string
	AllowHeaders  string
	MaxAge        string
	ExposeHeaders string
}

func generateCorsHeader(conf *config.CorsConfig) *corsHeader {
	if conf == nil {
		return nil
	}
	ch := &corsHeader{}

	if len(conf.AllowMethods) > 0 {
		allowMethods := utils.StringsChange(conf.AllowMethods, strings.ToUpper)
		ch.AllowMethods = strings.Join(allowMethods, ",")
	}
	if len(conf.AllowHeaders) > 0 {
		allowHeaders := utils.StringsChange(conf.AllowHeaders, http.CanonicalHeaderKey)
		ch.AllowHeaders = strings.Join(allowHeaders, ",")
	}
	if conf.MaxAge > time.Duration(0) {
		value := strconv.FormatInt(int64(conf.MaxAge/time.Second), 10)
		ch.MaxAge = value
	}
	if len(conf.ExposeHeaders) > 0 {
		exposeHeaders := utils.StringsChange(conf.ExposeHeaders, http.CanonicalHeaderKey)
		ch.ExposeHeaders = strings.Join(exposeHeaders, ",")
	}
	return ch
}

type ginsecurity struct {
	sslConfig    *config.SSLConfig
	corsConfig   *config.CorsConfig
	corsHeader   *corsHeader
	csrfConfig   *config.CsrfConfig
	noCacheStore bool
	fixedHeaders http.Header
}

var GetCSRFToken func(c *gin.Context) (string, error)

func newSecurity(conf *config.SecurityConfig) *ginsecurity {
	fh := make(http.Header)
	if conf.IENoOpen {
		fh.Set(h.XDownloadOpotions, "noopen")
	}
	if conf.NoStoreCache {
		fh.Set(h.CacheControl, "no-cache, no-store, max-age=0, must-revalidate")
		fh.Set(h.Pragma, "no-cache")
		fh.Set(h.Expires, "0")
	}
	if conf.ContentTypeNosniff {
		fh.Set(h.XContentTypeOptions, "nosniff")
	}
	if conf.FrameDeny {
		fh.Set(h.XFrameOptions, "DENY")
	} else if len(conf.CustomFrameOptionsValue) > 0 {
		fh.Set(h.XFrameOptions, conf.CustomFrameOptionsValue)
	}
	if len(conf.BrowserXssFilter) > 0 {
		fh.Set(h.XSSProtection, conf.BrowserXssFilter)
	}
	if conf.CSPConfig != nil && conf.CSPConfig.Enabled {
		cspHeader := conf.CSPConfig.GenerateHeader()
		if len(cspHeader) > 0 {
			if conf.CSPConfig.ReportOnly {
				fh.Set(h.ContentSecurityPolicyReportOnly, cspHeader)
			} else {
				fh.Set(h.ContentSecurityPolicy, cspHeader)
			}
		}
	}
	if conf.STS != nil {
		if value := conf.STS.Value(); len(value) > 0 {
			fh.Set(h.StrictTransportSecurity, value)
		}
	}

	gs := &ginsecurity{
		sslConfig:    conf.SSLConfig,
		corsConfig:   conf.CorsConfig,
		corsHeader:   generateCorsHeader(conf.CorsConfig),
		csrfConfig:   conf.CsrfConfig,
		noCacheStore: conf.NoStoreCache,
		fixedHeaders: fh,
	}
	if gs.csrfConfig != nil {
		GetCSRFToken = gs.getCsrfToken
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

func (gs *ginsecurity) checkSSL(c *gin.Context) bool {
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

func (gs *ginsecurity) checkOrigin(origin string) bool {
	if gs.corsConfig.IsAllowAllOrigin {
		return true
	}
	for _, o := range gs.corsConfig.AllowOrigins {
		if o == origin {
			return true
		}
	}
	for _, r := range gs.corsConfig.AllowRegexOrigins {
		if r.MatchString(origin) {
			return true
		}
	}

	return false
}

func (gs *ginsecurity) checkCORS(c *gin.Context) bool {
	conf := gs.corsConfig
	origin := c.Request.Header.Get(h.Origin)
	if len(origin) == 0 {
		return true
	}

	host := c.Request.Host
	if origin == utils.HTTP_SCHEME+"://"+host || origin == utils.HTTPS_SCHEME+"://"+host {
		return true
	}

	if !gs.checkOrigin(origin) && (conf.CustomAllowOrigin == nil || !conf.CustomAllowOrigin(c, origin)) {
		c.AbortWithStatus(http.StatusForbidden)
		return false
	}

	rHeader := gs.corsHeader
	header := c.Writer.Header()
	if c.Request.Method == http.MethodOptions {
		if !conf.IsAllowAllOrigin && conf.IsAllowCredentials {
			header.Set(h.AccessControlAllowCredentials, "true")
		}
		if rHeader.AllowMethods != "" {
			header.Set(h.AccessControlAllowMethod, rHeader.AllowMethods)
		}
		if rHeader.AllowHeaders != "" {
			header.Set(h.AccessControlAllowHeaders, rHeader.AllowHeaders)
		}
		if rHeader.MaxAge != "" {
			header.Set(h.AccessControlMaxAge, rHeader.MaxAge)
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
		c.AbortWithStatus(http.StatusNoContent)
	} else {
		if !conf.IsAllowAllOrigin && conf.IsAllowCredentials {
			header.Set(h.AccessControlAllowCredentials, "true")
		}
		if rHeader.ExposeHeaders != "" {
			header.Set(h.AccessControlExposeHeaders, rHeader.ExposeHeaders)
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

func (gs *ginsecurity) checkCSRF(c *gin.Context) bool {
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

func (gs *ginsecurity) getCsrfToken(c *gin.Context) (string, error) {
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

func (gs *ginsecurity) applyToContext(c *gin.Context) {
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

func New(config *config.SecurityConfig) gin.HandlerFunc {
	gs := newSecurity(config)
	return func(c *gin.Context) {
		gs.applyToContext(c)
	}
}
