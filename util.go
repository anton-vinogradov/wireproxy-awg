package wireproxy

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
)

const space = " "

func (d VirtualTun) preferIPv4() bool {
	if d.ResolveConfig != nil {
		switch d.ResolveConfig.ResolveStrategy {
		case "ipv4":
			return true
		case "ipv6":
			return false
		}
	}

	hasIPv4 := false
	if d.Conf != nil {
		for _, address := range d.Conf.Endpoint {
			if address.Is6() {
				return false
			}
			hasIPv4 = hasIPv4 || address.Is4()
		}
	}
	return hasIPv4
}

func responseWith(req *http.Request, statusCode int) *http.Response {
	statusText := http.StatusText(statusCode)
	body := "wireproxy:" + space + req.Proto + space + strconv.Itoa(statusCode) + space + statusText + "\r\n"

	return &http.Response{
		StatusCode: statusCode,
		Status:     statusText,
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}
