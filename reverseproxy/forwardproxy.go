package reverseproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	uuid "github.com/nu7hatch/gouuid"
)

type ForwardProxy struct {
	http.Transport
	ReverseProxyConfig
	servers []*http.Server
	rp      *httputil.ReverseProxy
	dialer  *net.Dialer
}

func (fp *ForwardProxy) Initialize(rpConfig ReverseProxyConfig) error {
	fp.ReverseProxyConfig = rpConfig
	fp.servers = make([]*http.Server, 0)

	fp.dialer = &net.Dialer{
		Timeout:   fp.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	fp.Transport = http.Transport{
		Dial:                fp.dialer.Dial,
		TLSHandshakeTimeout: fp.DialTimeout,
		MaxIdleConnsPerHost: 100,
		DisableCompression:  true,
	}
	fp.rp = &httputil.ReverseProxy{
		Director:      noopDirector,
		Transport:     fp,
		FlushInterval: fp.FlushInterval,
		BufferPool:    &bufferPool{},
	}
	return nil
}

func (fp *ForwardProxy) Listen(listener net.Listener, tlsconfig *tls.Config) {
	server := &http.Server{
		ReadTimeout:       fp.ReadTimeout,
		ReadHeaderTimeout: fp.ReadHeaderTimeout,
		WriteTimeout:      fp.WriteTimeout,
		IdleTimeout:       fp.IdleTimeout,
		Handler:           fp,
		TLSConfig:         tlsconfig,
	}
	fp.servers = append(fp.servers, server)
	server.Serve(listener)
}

func (fp *ForwardProxy) Stop() {
	for _, server := range fp.servers {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		server.Shutdown(ctx)
		cancel()
	}
}

func (fp *ForwardProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Host == "__ping__" && req.URL.Path == "/" {
		err := fp.Router.Healthcheck()
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(err.Error()))
			return
		}
		rw.WriteHeader(http.StatusOK)
		rw.Write(okResponse)
		return
	}
	if fp.RequestIDHeader != "" && fastHeaderGet(req.Header, fp.RequestIDHeader) == "" {
		unparsedID, err := uuid.NewV4()
		if err == nil {
			fastHeaderSet(req.Header, fp.RequestIDHeader, unparsedID.String())
		}
	}
	req.Header["Planb-X-Forwarded-For"] = req.Header["X-Forwarded-For"]
	fp.rp.ServeHTTP(rw, req)
}

func (fp *ForwardProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	reqData, err := fp.Router.ChooseBackend(req.Host)
	if err != nil {
		fmt.Errorf("error in ChooseBackend: %s", err)
		return nil, err
	}
	u, err := url.Parse(reqData.Backend)
	if err != nil {
		fmt.Errorf("error in url.Parse: %s", err)
		return nil, err
	}
	fp.Transport.Proxy = http.ProxyURL(u)
	rsp, err := fp.Transport.RoundTrip(req)
	if err != nil {
		fmt.Errorf("error in RoundTrip: %s", err)
		return nil, err
	}
	return rsp, nil
}
