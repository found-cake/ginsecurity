package checker

import (
	"net/http"
	"strings"

	"github.com/found-cake/ginsecurity/config"
	"github.com/found-cake/ginsecurity/utils"
	"github.com/gin-gonic/gin"
)

type SSLChecker struct {
	conf *config.SSLConfig
}

func NewSslChecker(conf *config.SSLConfig) *SSLChecker {
	if conf == nil {
		return nil
	}
	return &SSLChecker{conf}
}

func (c *SSLChecker) isSSLReq(req *http.Request) bool {
	if strings.EqualFold(req.URL.Scheme, utils.HTTPS_SCHEME) || req.TLS != nil {
		return true
	}
	for k, v := range c.conf.ProxyHeaders {
		k = http.CanonicalHeaderKey(k)
		headerValues, ok := req.Header[k]

		if !ok || len(headerValues) == 0 {
			continue
		}

		for _, headerValue := range headerValues {
			headerValue = strings.TrimSpace(headerValue)
			if strings.EqualFold(headerValue, v) {
				return true
			}
		}
	}
	return false
}

func (checker *SSLChecker) Check(c *gin.Context) bool {
	if !checker.conf.IsRedirect {
		return true
	}

	req := c.Request
	if checker.isSSLReq(req) {
		return true
	}

	url := req.URL
	url.Scheme = utils.HTTPS_SCHEME

	if len(checker.conf.Host) > 0 {
		url.Host = checker.conf.Host
	} else {
		url.Host = req.Host
	}

	c.Redirect(http.StatusMovedPermanently, url.String())
	c.Abort()
	return false
}
