package method

import "net/http"

type Method string

const (
	GET     Method = http.MethodGet
	POST    Method = http.MethodPost
	PUT     Method = http.MethodPut
	PATCH   Method = http.MethodPatch
	DELETE  Method = http.MethodDelete
	HEAD    Method = http.MethodHead
	OPTIONS Method = http.MethodOptions
)

var ALL []Method = []Method{GET, POST, PUT, PUT, PATCH, DELETE, HEAD, OPTIONS}
