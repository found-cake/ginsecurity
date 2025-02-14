package utils

import "net/http"

var HTTP_METHOD_ALL = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodHead,
	http.MethodOptions,
}

const HTTPS_SCHEME = "https"
const HTTP_SCHEME = "http"
