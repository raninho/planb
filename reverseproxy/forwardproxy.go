package reverseproxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	uuid "github.com/nu7hatch/gouuid"
)

var (
	hostname, _ = os.Hostname()

	dir      = path.Join(os.Getenv("HOME"), ".mitm")
	keyFile  = path.Join(dir, "ca-key.pem")
	certFile = path.Join(dir, "ca-cert.pem")
)

type ForwardProxy struct {
	http.Transport
	ReverseProxyConfig
	CA *tls.Certificate
	servers []*http.Server
	rp      *httputil.ReverseProxy
	dialer  *net.Dialer
	TLSServerConfig *tls.Config
	TLSClientConfig *tls.Config
	FlushInterval time.Duration
	Wrap func(upstream http.Handler) http.Handler
}

func loadCA() (cert tls.Certificate, err error) {
	// TODO(kr): check file permissions
	cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	if os.IsNotExist(err) {
		cert, err = genCA()
	}
	if err == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}
	return
}

func genCA() (cert tls.Certificate, err error) {
	hostname, _ := os.Hostname()
	err = os.MkdirAll(dir, 0700)
	if err != nil {
		return
	}
	certPEM, keyPEM, err := GenCA(hostname)
	if err != nil {
		return
	}
	cert, _ = tls.X509KeyPair(certPEM, keyPEM)
	err = ioutil.WriteFile(certFile, certPEM, 0400)
	if err == nil {
		err = ioutil.WriteFile(keyFile, keyPEM, 0400)
	}
	return cert, err
}

func GenCA(name string) (certPEM, keyPEM []byte, err error) {
	caMaxAge := 5 * 365 * 24 * time.Hour
	caUsage := x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              caUsage,
		BasicConstraintsValid: true,
		IsCA:               true,
		MaxPathLen:         2,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
	if err != nil {
		return
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: keyDER,
	})
	return
}

type cloudToButtResponse struct {
	http.ResponseWriter

	sub         bool
	wroteHeader bool
}

func (w *cloudToButtResponse) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	ctype := w.Header().Get("Content-Type")
	if strings.HasPrefix(ctype, "text/html") {
		w.sub = true
	}
	w.ResponseWriter.WriteHeader(code)
}

var (
	cloud = []byte("the cloud")
	butt  = []byte("my   butt")
)

func (w *cloudToButtResponse) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(200)
	}
	if w.sub {
		p = bytes.Replace(p, cloud, butt, -1)
	}
	return w.ResponseWriter.Write(p)
}

func cloudToButt(upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Accept-Encoding", "")
		upstream.ServeHTTP(&cloudToButtResponse{ResponseWriter: w}, r)
	})
}


func (fp *ForwardProxy) Initialize(rpConfig ReverseProxyConfig) error {
	fp.ReverseProxyConfig = rpConfig
	fp.servers = make([]*http.Server, 0)

	ca, err := loadCA()
	if err!= nil {
		return err
	}

	fp.CA = &ca
	fp.TLSServerConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	fp.Wrap = cloudToButt

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

func dnsName(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

func genKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

func genCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()
	if !ca.Leaf.IsCA {
		return nil, errors.New("CA cert is not a CA")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature |
			x509.KeyUsageContentCommitment |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

func handshake(w http.ResponseWriter, config *tls.Config) (net.Conn, error) {
	var okHeader = []byte("HTTP/1.1 200 OK\r\n\r\n")

	raw, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		http.Error(w, "no upstream", 503)
		return nil, err
	}
	if _, err = raw.Write(okHeader); err != nil {
		raw.Close()
		return nil, err
	}
	conn := tls.Server(raw, config)
	err = conn.Handshake()
	if err != nil {
		conn.Close()
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func httpDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "http"
}

func httpsDirector(r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
}

// A oneShotDialer implements net.Dialer whos Dial only returns a
// net.Conn as specified by c followed by an error for each subsequent Dial.
type oneShotDialer struct {
	c  net.Conn
	mu sync.Mutex
}

func (d *oneShotDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c == nil {
		return nil, errors.New("closed")
	}
	c := d.c
	d.c = nil
	return c, nil
}

func (fp *ForwardProxy) HandleTunneling(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		sconn *tls.Conn
		name  = dnsName(r.Host)
	)

	if name == "" {
		log.Println("cannot determine cert name for " + r.Host)
		http.Error(w, "no upstream", 503)
		return
	}

	provisionalCert, err := genCert(fp.CA, []string{name})
	if err != nil {
		log.Println("cert", err)
		http.Error(w, "no upstream", 503)
		return
	}

	sConfig := new(tls.Config)
	if fp.TLSServerConfig != nil {
		*sConfig = *fp.TLSServerConfig
	}
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
		provisionalCert, err := genCert(fp.CA, []string{name})
		if err != nil {
			log.Println("cert", err)
			http.Error(w, "no upstream", 503)
			return nil, err
		}
		return provisionalCert, nil
	}

	cconn, err := handshake(w, sConfig)
	if err != nil {
		log.Println("handshake", r.Host, err)
		return
	}
	defer cconn.Close()
	if sconn == nil {
		log.Println("could not determine cert name for " + r.Host)
		return
	}
	defer sconn.Close()

	//od := &oneShotDialer{c: sconn}
	/*rp := &httputil.ReverseProxy{
		Director:      httpsDirector,
		Transport:     &http.Transport{DialTLS: od.Dial},
		FlushInterval: fp.FlushInterval,
	}*/

	ch := make(chan int)
	wc := &onCloseConn{cconn, func() { ch <- 0 }}
	http.Serve(&oneShotListener{wc}, fp.Wrap(fp.rp))
	<-ch
}

// A oneShotListener implements net.Listener whos Accept only returns a
// net.Conn as specified by c followed by an error for each subsequent Accept.
type oneShotListener struct {
	c net.Conn
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if l.c == nil {
		return nil, errors.New("closed")
	}
	c := l.c
	l.c = nil
	return c, nil
}

func (l *oneShotListener) Close() error {
	return nil
}

func (l *oneShotListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

// A onCloseConn implements net.Conn and calls its f on Close.
type onCloseConn struct {
	net.Conn
	f func()
}

func (c *onCloseConn) Close() error {
	if c.f != nil {
		c.f()
		c.f = nil
	}
	return c.Conn.Close()
}

func (fp *ForwardProxy) HandleTunneling8(w http.ResponseWriter, r *http.Request) {
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

	dest_conn, err := fp.dialer.Dial("tcp", "localhost:7000")
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

	/*err = r.Write(client_conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}*/

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
	fmt.Println("entrou no RoundTrip")
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
	fmt.Println("send Backend: ", req.Host)
	return fp.Send(req, reqData.Backend)
}

func (fp *ForwardProxy) Send(req *http.Request, backend string) (*http.Response, error) {
	fmt.Println("entrou no Send with backend:", backend)
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

	req.URL.Scheme = "https"
	print("req.URL.Scheme:", req.URL.Scheme)
	print("u.Scheme:", u.Scheme)

	requestDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(requestDump))

	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	fmt.Println("antes do ProxyURL", req.Host, req.URL.Host)
	fp.Transport.Proxy = http.ProxyURL(u)
	fmt.Println("antes do RoundTrip")
	rsp, err := fp.Transport.RoundTrip(req)
	if err != nil {
		fmt.Errorf("error in RoundTrip: %s", err)
		return nil, err
	}

	fmt.Println("depois do RoundTrip")
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

	fmt.Println("reqData.Backend:", reqData.Backend)
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
