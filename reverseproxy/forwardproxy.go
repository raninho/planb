package reverseproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	uuid "github.com/nu7hatch/gouuid"

	"github.com/tsuru/planb/mitm"
)

type ForwardProxy struct {
	http.Transport
	ReverseProxyConfig
	servers []*http.Server
	rp      *httputil.ReverseProxy
	dialer  *net.Dialer

	//mitm TLS
	CA *tls.Certificate
	TLSServerConfig *tls.Config
	TLSClientConfig *tls.Config
}

func (fp *ForwardProxy) Initialize(rpConfig ReverseProxyConfig) error {
	fp.ReverseProxyConfig = rpConfig
	fp.servers = make([]*http.Server, 0)

	ca, err := mitm.LoadCA("./certficates/mitm-ca-cert.pem", "./certficates/mitm-ca-key.pem")
	if err!= nil {
		panic(err.Error())
		return err
	}

	fp.CA = &ca
	fp.TLSServerConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	fp.dialer = &net.Dialer{
		Timeout:   fp.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	fp.Transport = http.Transport{
		Dial:                fp.dialer.Dial,
		TLSHandshakeTimeout: fp.DialTimeout,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		TLSNextProto:    make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
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

func (fp *ForwardProxy) HandleTunneling(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "no upstream", 503)
		return
	}

	provisionalCert, err := mitm.GenCert(fp.CA, []string{host})
	if err != nil {
		http.Error(w, "no upstream", 503)
		return
	}

	sConfig := new(tls.Config)
	if fp.TLSServerConfig != nil {
		*sConfig = *fp.TLSServerConfig
	}

	var sconn *tls.Conn
	sConfig.Certificates = []tls.Certificate{*provisionalCert}
	sConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cConfig := new(tls.Config)
		if fp.TLSClientConfig != nil {
			*cConfig = *fp.TLSClientConfig
		}
		cConfig.ServerName = hello.ServerName
		sconn, err = tls.Dial("tcp", r.Host, cConfig)
		if err != nil {
			log.Println("dial", r.Host, err)
			return nil, err
		}
		provisionalCert, err := mitm.GenCert(fp.CA, []string{host})
		if err != nil {
			log.Println("cert", err)
			http.Error(w, "no upstream", 503)
			return nil, err
		}
		return provisionalCert, nil
	}

	cconn, err := mitm.Handshake(w, sConfig)
	if err != nil {
		http.Error(w, "no handshake", 503)
		return
	}
	defer cconn.Close()

	if sconn == nil {
		http.Error(w, "no sconn", 503)
		return
	}
	defer sconn.Close()

	ch := make(chan int)
	wc := &mitm.OnCloseConn{cconn, func() { ch <- 0 }}
	http.Serve(&mitm.OneShotListener{wc}, fp.rp)

	<-ch
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
	req.Header["Planb-X-Preference-Proxy"] = req.Header["Proxy-Authorization"]

	if req.Method == http.MethodConnect {
		fp.HandleTunneling(rw, req)
		return
	}

	fp.rp.ServeHTTP(rw, req)
}

func (fp *ForwardProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	for _, cookie := range req.Cookies() {
		if cookie.Name == "planb" {
			return fp.Send(req, cookie.Value)
		}
	}

	preference := getPreferenceProviderName(req.Header.Get("Planb-X-Preference-Proxy"))
	reqData, err := fp.ChooseBackend(req.Host, preference )
	if err != nil {
		fmt.Errorf("error in ChooseBackend: %s", err)
		return nil, err
	}
	return fp.Send(req, reqData.Backend)
}

func (fp *ForwardProxy) Send(req *http.Request, backend string) (*http.Response, error) {
	u, err := url.Parse(backend)
	if err != nil {
		fmt.Errorf("error in url.Parse: %s", err)
		return nil, err
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}

	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	fp.Transport.Proxy = http.ProxyURL(u)
	rsp, err := fp.Transport.RoundTrip(req)
	if err != nil {
		fmt.Errorf("error in RoundTrip: %s", err)
		return nil, err
	}
	
	cookie := http.Cookie{Name: "planb", Value: u.String(), Expires: time.Now().Add(5 * time.Minute)}
	rsp.Header.Add("Set-Cookie", cookie.String())
	return rsp, nil
}

func (fp *ForwardProxy) ChooseBackend(host string, preferenceProvider string) (*RequestData, error) {
	if preferenceProvider != "" {
		reqData, err := fp.Router.ChooseBackend(preferenceProvider)
		if err == nil {
			return reqData, nil
		}
	}

	reqData, err := fp.Router.ChooseBackend("DEFAULT")
	if err != nil {
		return nil, err
	}

	reqData, err = fp.Router.ChooseBackend(reqData.Backend)
	if err != nil {
		return nil, err
	}

	return reqData, nil
}

func getPreferenceProviderName(auth string) (preferenceProvider string) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[s+1:]
}
