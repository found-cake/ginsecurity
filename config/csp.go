package config

import (
	"sort"
	"strings"

	"github.com/found-cake/ginsecurity/utils"
)

type CSPConfig struct {
	Enabled         bool
	ReportOnly      bool
	DirectivesMap   map[string][]string
	CustomCSPHeader string
}

func (c *CSPConfig) initMap() {
	if c.DirectivesMap == nil {
		c.DirectivesMap = make(map[string][]string)
	}
}

func (c *CSPConfig) SetDirective(directive string, sources ...string) *CSPConfig {
	c.initMap()
	c.DirectivesMap[directive] = sources
	return c
}

func (c *CSPConfig) AddDirective(directive string, sources ...string) *CSPConfig {
	c.initMap()
	c.DirectivesMap[directive] = append(c.DirectivesMap[directive], sources...)
	return c
}

func (c *CSPConfig) RemoveDirective(directive string) *CSPConfig {
	if c.DirectivesMap != nil {
		delete(c.DirectivesMap, directive)
	}
	return c
}

func (c *CSPConfig) GenerateHeader() string {
	if len(c.CustomCSPHeader) > 0 {
		return c.CustomCSPHeader
	}

	if len(c.DirectivesMap) == 0 {
		return ""
	}

	var directiveKeys []string
	for directive, values := range c.DirectivesMap {
		checkMap := make(map[string]bool)
		var uniqueSources []string
		for _, value := range values {
			if _, ok := checkMap[value]; !ok {
				checkMap[value] = true
				uniqueSources = append(uniqueSources, value)
			}
		}
		directiveKeys = append(directiveKeys, directive)
		c.DirectivesMap[directive] = uniqueSources
	}
	sort.Strings(directiveKeys)

	var directives []string
	for _, directive := range directiveKeys {
		sources := c.DirectivesMap[directive]
		if len(sources) > 0 {
			directives = append(directives, directive+" "+strings.Join(sources, " "))
		} else {
			directives = append(directives, directive)
		}
	}

	return strings.Join(directives, "; ")
}

// builder
func NewCSPBuilder() *CSPConfig {
	return &CSPConfig{
		Enabled:       true,
		ReportOnly:    false,
		DirectivesMap: make(map[string][]string),
	}
}

func (c *CSPConfig) EnableReportOnly() *CSPConfig {
	c.ReportOnly = true
	return c
}

func (c *CSPConfig) DisableReportOnly() *CSPConfig {
	c.ReportOnly = false
	return c
}

// default
func DefaultCSPConfig() *CSPConfig {
	return NewCSPBuilder().
		SetDirective(utils.CSPDefaultSrc, utils.CSPSelf).
		SetDirective(utils.CSPObjectSrc, utils.CSPNone)
}
