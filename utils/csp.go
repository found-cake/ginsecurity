package utils

// Directive
const (
	CSPDefaultSrc              = "default-src"
	CSPScriptSrc               = "script-src"
	CSPStyleSrc                = "style-src"
	CSPImgSrc                  = "img-src"
	CSPConnectSrc              = "connect-src"
	CSPFontSrc                 = "font-src"
	CSPObjectSrc               = "object-src"
	CSPMediaSrc                = "media-src"
	CSPFrameSrc                = "frame-src"
	CSPChildSrc                = "child-src"
	CSPFrameAncestors          = "frame-ancestors"
	CSPFormAction              = "form-action"
	CSPBaseURI                 = "base-uri"
	CSPReportUri               = "report-uri"
	CSPReportTo                = "report-to"
	CSPUpgradeInsecureRequests = "upgrade-insecure-requests"
	CSPBlockAllMixedContent    = "block-all-mixed-content"
)

// Values
const (
	CSPSelf          = "'self'"
	CSPNone          = "'none'"
	CSPUnsafeInline  = "'unsafe-inline'"
	CSPUnsafeEval    = "'unsafe-eval'"
	CSPStrictDynamic = "'strict-dynamic'"
	CSPWildcard      = "*"
	CSPData          = "data:"
	CSPBlob          = "blob:"
	CSPHttps         = "https:"
)
