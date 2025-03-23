package checker

import (
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

type CorsChecker struct {
	conf         *config.CorsConfig
	fHeader      *corsHeader
	noCacheStore bool
}

func NewCorsChcker(conf *config.CorsConfig, noCacheStore bool) *CorsChecker {
	if conf == nil {
		return nil
	}
	return &CorsChecker{
		conf:         conf,
		fHeader:      generateCorsHeader(conf),
		noCacheStore: noCacheStore,
	}
}

func (checker *CorsChecker) checkOrigin(origin string) bool {
	if checker.conf.IsAllowAllOrigin {
		return true
	}
	for _, o := range checker.conf.AllowOrigins {
		if o == origin {
			return true
		}
	}
	for _, r := range checker.conf.AllowRegexOrigins {
		if r.MatchString(origin) {
			return true
		}
	}

	return false
}

func (checker *CorsChecker) Check(c *gin.Context) bool {
	conf := checker.conf
	origin := c.Request.Header.Get(h.Origin)
	if len(origin) == 0 {
		return true
	}

	host := c.Request.Host
	if origin == utils.HTTP_SCHEME+"://"+host || origin == utils.HTTPS_SCHEME+"://"+host {
		return true
	}

	if !checker.checkOrigin(origin) && (conf.CustomAllowOrigin == nil || !conf.CustomAllowOrigin(c, origin)) {
		c.AbortWithStatus(http.StatusForbidden)
		return false
	}

	rHeader := checker.fHeader
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
			if !checker.noCacheStore {
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
			if !checker.noCacheStore {
				header.Set(h.Vary, h.Origin)
			}
		}
	}

	return true
}
