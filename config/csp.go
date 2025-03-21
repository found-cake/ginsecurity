package config

import (
	"strings"
)

const (
	CSPDefaultSrc     = "default-src"
	CSPScriptSrc      = "script-src"
	CSPStyleSrc       = "style-src"
	CSPImgSrc         = "img-src"
	CSPConnectSrc     = "connect-src"
	CSPFontSrc        = "font-src"
	CSPObjectSrc      = "object-src"
	CSPMediaSrc       = "media-src"
	CSPFrameSrc       = "frame-src"
	CSPChildSrc       = "child-src"
	CSPFrameAncestors = "frame-ancestors"
	CSPFormAction     = "form-action"
	CSPReportUri      = "report-uri"
	CSPReportTo       = "report-to"
)

const (
	CSPSelf          = "'self'"
	CSPNone          = "'none'"
	CSPUnsafeInline  = "'unsafe-inline'"
	CSPUnsafeEval    = "'unsafe-eval'"
	CSPStrictDynamic = "'strict-dynamic'"
)

type CSPConfig struct {
	Enabled         bool
	ReportOnly      bool
	DirectivesMap   map[string][]string
	CustomCSPHeader string
}

func (c *CSPConfig) AddDirective(directive string, sources ...string) *CSPConfig {
	if c.DirectivesMap == nil {
		c.DirectivesMap = make(map[string][]string)
	}
	c.DirectivesMap[directive] = append(c.DirectivesMap[directive], sources...)
	return c
}

func (c *CSPConfig) GenerateHeader() string {
	if len(c.CustomCSPHeader) > 0 {
		return c.CustomCSPHeader
	}

	if len(c.DirectivesMap) == 0 {
		return ""
	}

	var directives []string

	for directive, sources := range c.DirectivesMap {
		if len(sources) > 0 {
			directives = append(directives, directive+" "+strings.Join(sources, " "))
		} else {
			directives = append(directives, directive)
		}
	}

	return strings.Join(directives, "; ")
}

func DefaultCSPConfig() *CSPConfig {
	config := &CSPConfig{
		Enabled:    true,
		ReportOnly: false,
	}

	config.AddDirective(CSPDefaultSrc, CSPSelf)
	config.AddDirective(CSPScriptSrc, CSPSelf)
	config.AddDirective(CSPStyleSrc, CSPSelf)
	config.AddDirective(CSPImgSrc, CSPSelf)
	config.AddDirective(CSPConnectSrc, CSPSelf)
	config.AddDirective(CSPObjectSrc, CSPNone)
	return config
}
