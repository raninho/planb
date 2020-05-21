package reverseproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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

func (fp *ForwardProxy) HandleTunneling2(w http.ResponseWriter, r *http.Request) {
	fmt.Println("entrou no handleTunneling")
	preference := getPreferenceProviderName(r.Header.Get("Planb-X-Preference-Proxy"))
	reqData, err := fp.ChooseBackend(r.Host, preference )
	if err != nil {
		fmt.Errorf("error in ChooseBackend: %s", err)
		return
	}

	url, err := url.Parse(reqData.Backend)
	if err != nil {
		fmt.Errorf("error in url.Parse: %s", err)
		return
	}
	fmt.Println("url.Host:", url.Host)
	fmt.Println("url.Host:", r.Host)

	//r.URL.Scheme = "https"
	fmt.Println("req.URL.Scheme:", r.URL.Scheme)
	fmt.Println("u.Scheme:", url.Scheme)

	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

	fp.Transport.Proxy = http.ProxyURL(url)
	rsp, err := fp.Transport.RoundTrip(r)
	if err != nil {
		fmt.Errorf("error in RoundTrip: %s", err)
		return
	}

	cookie := http.Cookie{Name: "planb", Value: url.String(), Expires: time.Now().Add(5 * time.Minute)}
	rsp.Header.Add("Set-Cookie", cookie.String())
	rsp.Write(w)
}


/*func (fp *ForwardProxy) HandleTunneling(w http.ResponseWriter, r *http.Request) {
	print("entrou no handleTunneling")
	preference := getPreferenceProviderName(r.Header.Get("Planb-X-Preference-Proxy"))
	reqData, err := fp.ChooseBackend(r.Host, preference )
	if err != nil {
		fmt.Errorf("error in ChooseBackend: %s", err)
		return
	}
	fmt.Println("reqData.Backend:", reqData.Backend)
	u, err := url.Parse(reqData.Backend)
	if err != nil {
		fmt.Errorf("error in url.Parse: %s", err)
		return
	}
	fmt.Println("u:", u.String())
	target, err := url.Parse(reqData.Backend)
	if err != nil {
		fmt.Errorf("error in url.Parse: %s", err)
		return
	}
	fmt.Println("u:", target.String())
	fp.Transport.Proxy = http.ProxyURL(u)
	fp.
	rsp, err := fp.Transport.RoundTrip(r)
}*/

func (fp *ForwardProxy) HandleTunneling4(w http.ResponseWriter, r *http.Request) {
	print("entrou no handleTunneling")
	preference := getPreferenceProviderName(r.Header.Get("Planb-X-Preference-Proxy"))
	reqData, err := fp.ChooseBackend(r.Host, preference )
	if err != nil {
		fmt.Errorf("error in ChooseBackend: %s", err)
		return
	}

	print("reqData:", reqData.Backend)

	w.WriteHeader(http.StatusCreated)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	defer client_conn.Close()

	resp, err := fp.Send(r, reqData.Backend)
	if err != nil {
		print("err:", err.Error())
	}
	fmt.Println("status:", resp.Status)
	io.Copy(client_conn, resp.Body)
}

func (fp *ForwardProxy) HandleTunneling(w http.ResponseWriter, r *http.Request) {
	print("entrou no handleTunneling")
	print(r.UserAgent())
	preference := getPreferenceProviderName(r.Header.Get("Planb-X-Preference-Proxy"))
	reqData, err := fp.ChooseBackend(r.Host, preference )
	if err != nil {
		fmt.Errorf("error in ChooseBackend: %s", err)
		return
	}

	print("reqData:", reqData.Backend)

	url, err := url.Parse(reqData.Backend)
	if err != nil {
		fmt.Errorf("error in url.Parse: %s", err)
		return
	}
	print("url.Host:", url.Host)
	print("url.Host:", r.Host)

	/*resp, err := fp.Send(r, reqData.Backend)
	if err != nil {
		print("err:", err.Error())
	}

	return resp, err*/

	dest_conn, err := fp.dialer.Dial("tcp", url.Host)
	if err != nil {
		print("err:", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer dest_conn.Close()
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	print("antes do hijack:")
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	defer client_conn.Close()

	var clientIP string
	if clientIP, _, err = net.SplitHostPort(r.RemoteAddr); err == nil {
		if prior, ok := r.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		//fastHeaderSet(r.Header, "X-Forwarded-For", clientIP)
	}

	requestDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

	err = r.Write(client_conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}

	go cp(dest_conn, client_conn)
	go cp(client_conn, dest_conn)
	<-errc

	print("saiu no handleTunneling")
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
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
			fmt.Println("send cookie")
			return fp.Send(req, cookie.Value)
		}
	}

	preference := getPreferenceProviderName(req.Header.Get("Planb-X-Preference-Proxy"))
	reqData, err := fp.ChooseBackend(req.Host, preference )
	if err != nil {
		fmt.Errorf("error in ChooseBackend: %s", err)
		return nil, err
	}
	fmt.Println("send Backend")
	return fp.Send(req, reqData.Backend)
}

func (fp *ForwardProxy) Send(req *http.Request, backend string) (*http.Response, error) {
	u, err := url.Parse(backend)
	if err != nil {
		fmt.Errorf("error in url.Parse: %s", err)
		return nil, err
	}

	for name, values := range req.Header {
		for _, value := range values {
			fmt.Println(name, value)
		}
	}

	//req.URL.Scheme = "https"
	print("req.URL.Scheme:", req.URL.Scheme)
	print("u.Scheme:", u.Scheme)

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
