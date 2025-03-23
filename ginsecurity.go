package ginsecurity

import (
	"net/http"

	"github.com/found-cake/ginsecurity/checker"
	"github.com/found-cake/ginsecurity/config"
	h "github.com/found-cake/ginsecurity/utils/header"
	"github.com/gin-gonic/gin"
)

type ginsecurity struct {
	sslChecker   *checker.SSLChecker
	corsChecker  *checker.CorsChecker
	csrfChecker  *checker.CsrfChecker
	fixedHeaders http.Header
}

var GetCSRFToken checker.GetCSRFTokenFunc

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

	var csrfChecker *checker.CsrfChecker
	csrfChecker, GetCSRFToken = checker.NewCsrfChecker(conf.CsrfConfig)

	gs := &ginsecurity{
		sslChecker:   checker.NewSslChecker(conf.SSLConfig),
		corsChecker:  checker.NewCorsChcker(conf.CorsConfig, conf.NoStoreCache),
		csrfChecker:  csrfChecker,
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

func (gs *ginsecurity) applyToContext(c *gin.Context) {
	gs.writeHeader(c)
	if gs.sslChecker != nil && !gs.sslChecker.Check(c) {
		return
	}
	if gs.corsChecker != nil && !gs.corsChecker.Check(c) {
		return
	}
	if gs.csrfChecker != nil && !gs.csrfChecker.Check(c) {
		return
	}
}

func New(config *config.SecurityConfig) gin.HandlerFunc {
	gs := newSecurity(config)
	return func(c *gin.Context) {
		gs.applyToContext(c)
	}
}
