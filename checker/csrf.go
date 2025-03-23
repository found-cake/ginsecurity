package checker

import (
	"net/http"

	"github.com/found-cake/ginsecurity/config"
	"github.com/found-cake/ginsecurity/utils"
	"github.com/gin-gonic/gin"
)

type GetCSRFTokenFunc func(c *gin.Context) string

type CsrfChecker struct {
	conf *config.CsrfConfig
}

func NewCsrfChecker(conf *config.CsrfConfig) (*CsrfChecker, GetCSRFTokenFunc) {
	if conf == nil {
		return nil, nil
	}
	return &CsrfChecker{conf}, func(c *gin.Context) string {
		token := conf.TokenGenerator()
		session := conf.SessionGetter(c)
		session.Set(utils.CsrfToken, token)
		session.Save()
		return token
	}
}

func (checker *CsrfChecker) Check(c *gin.Context) bool {
	if utils.InArray(checker.conf.IgnoreMethods, c.Request.Method) {
		return true
	}
	if utils.InArray(checker.conf.IgnorePath, c.Request.URL.Path) {
		return true
	}

	session := checker.conf.SessionGetter(c)
	token, ok := session.Get(utils.CsrfToken).(string)
	if !ok || len(token) == 0 || checker.conf.TokenGetter(c) != token {
		c.AbortWithStatus(http.StatusBadRequest)
		return false
	}

	return true
}
