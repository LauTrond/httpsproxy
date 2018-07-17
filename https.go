package httpsproxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/tls"
	"encoding/pem"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

func SignHost(hostname string, rootCerPem, rootKeyPem []byte, validUntil time.Time) (_cerPem, _keyPem []byte, _err error) {
	rootCerPemBlock,_ := pem.Decode(rootCerPem)
	rootCer, err := x509.ParseCertificate(rootCerPemBlock.Bytes)
	if err != nil { return nil, nil, err }

	rootKeyPemBlock, _ := pem.Decode(rootKeyPem)
	rootKey, err := x509.ParsePKCS1PrivateKey(rootKeyPemBlock.Bytes)
	if err != nil { return nil, nil, err }

	randBytes := make([]byte, 16)
	_,err = rand.Read(randBytes)
	if err != nil { return nil, nil, err }

	cer := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(randBytes),
		Subject : rootCer.Subject,
		NotBefore: time.Now(),
		NotAfter: validUntil,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{ x509.ExtKeyUsageServerAuth },
	}

	if ip := net.ParseIP(hostname) ; ip != nil {
		cer.IPAddresses = []net.IP{ ip }
	} else {
		cer.DNSNames = []string{ hostname }
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return nil, nil, err }

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	cerBytes,err := x509.CreateCertificate(rand.Reader, cer, rootCer, &key.PublicKey, rootKey)
	if err != nil { return nil, nil, err }

	cerPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cerBytes,
	})

	return cerPem, keyPem, nil
}

func SignRoot(validUntil time.Time) (_cerPem, _keyPem []byte, _err error) {
	randBytes := make([]byte, 16)
	_,err := rand.Read(randBytes)
	if err != nil { return nil, nil, err }

	cer := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(randBytes),
		Subject : pkix.Name{
			Organization: []string{ reflect.TypeOf(SignRoot).PkgPath() },
		},
		NotBefore: time.Now(),
		NotAfter: validUntil,
		BasicConstraintsValid: true,
		IsCA: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment |  x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{ x509.ExtKeyUsageServerAuth },
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return nil, nil, err }

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	cerBytes,err := x509.CreateCertificate(rand.Reader, cer, cer, &key.PublicKey, key)
	if err != nil { return nil, nil, err }

	cerPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cerBytes,
	})

	return cerPem, keyPem, nil
}

type virtualListener struct {
	closed chan struct{}
	chanConn chan net.Conn
}

func (l *virtualListener) add(c net.Conn) error {
	select {
		case l.chanConn <- c:
			return nil
		case <-l.closed:
			return fmt.Errorf("closed")
	}
}

func (l *virtualListener) Accept() (net.Conn, error) {
	select {
		case c := <-l.chanConn:
			return c, nil
		case <-l.closed:
			return nil, fmt.Errorf("closed")
	}
}

func (l *virtualListener) Close() error {
	select {
	case <-l.closed:
	default:
			close(l.closed)
	}
	return nil
}

type virtualAddr struct{}

func (virtualAddr) Network() string {
	return "virtual"
}

func (virtualAddr) String() string {
	return "virtual"
}

func (l *virtualListener) Addr() net.Addr {
	return virtualAddr{}
}

func VirtualListen() (net.Listener, func(net.Conn)error) {
	l := &virtualListener{
		closed : make(chan struct{}),
		chanConn : make(chan net.Conn),
	}
	return l, l.add
}

type virtualHost struct {
	ready <-chan struct{}
	cert *tls.Certificate
	err error
	deadline time.Time
}

func (vh *virtualHost) Expired() bool {
	return time.Now().After(vh.deadline)
}

func NewHttpsHijacker(handler http.Handler, rootCerPem, rootPkPem []byte) *HttpsHijacker {
	return &HttpsHijacker{
		RootCerPem: rootCerPem,
		RootPkPem: rootPkPem,
		ProxyHandler: handler,
	}
}

//这是一个通过中间人攻击解包HTTPS的模块
//1. 赋值RootCerPem, RootPkPem自签发根证书、
//   赋值ProxyHandler处理后续的HTTP请求。
//2. 调用Serve方法（堵塞），模块进入处理请求状态。
//   调用Shutdown，Serve方法返回，处理停止。
//3. 对每个请求连接到hostname并准备进行HTTPS请求的连接c，
//   调用HandleTunnel，该连接的所有请求将通过ProxyHandler回调。
//
// 模块使用RootCerPem、RootPkPem签发hostname的证书，并对c进行服务端TLS握手。
// 第一次调用ProxyHandler需要签发证书，耗时约1秒。模块会缓存证书。
type HttpsHijacker struct {
	//根证书
	RootCerPem, RootPkPem []byte

	//处理代理请求的回调。 ServeHTTP(w,r): r.URI 是包含网站名的完整URL。
	ProxyHandler http.Handler

	//可选参数，HttpServer的各种设置（例如超时）会被使用，Handler无效。
	HttpServer *http.Server

	//可选参数，证书缓存
	//如果为nil，首次启用时初始化为 NewLRUCache(1000)
	VirtualHostCache Cache

	initOnce sync.Once
	mtx sync.RWMutex

	dst map[string]string
	tlsConfig *tls.Config
	httpServer *http.Server

	listener net.Listener
	handleConnFunc func(c net.Conn)error
}

func (e *HttpsHijacker) checkInit() {
	e.initOnce.Do(e.init)
}

func (e *HttpsHijacker) init() {
	if e.VirtualHostCache == nil {
		e.VirtualHostCache = NewLRUCache(1000)
	}
	e.dst = map[string]string{}
	e.tlsConfig = &tls.Config{
		GetCertificate : e.getCertificate,
	}
	e.httpServer = &http.Server{}
	if e.HttpServer != nil {
		*e.httpServer = *e.HttpServer
	}
	e.httpServer.Handler = http.HandlerFunc(e.serveHTTP)

	e.listener,e.handleConnFunc = VirtualListen()
}

func (e *HttpsHijacker) Serve() error {
	e.checkInit()
	return e.httpServer.Serve(e.listener)
}

func (e *HttpsHijacker) Shutdown(ctx context.Context) error {
	e.checkInit()
	return e.httpServer.Shutdown(ctx)
}

//实现TunnelHandler
func (e *HttpsHijacker) HandleTunnel(c net.Conn, hostname string) error {
	e.checkInit()
	clientAddr := c.RemoteAddr().String()
	err := e.putDst(clientAddr, hostname)
	if err != nil {
		c.Close()
		return err
	}
	c = HookCloseConn(c, func(){
		e.removeDst(clientAddr)
	})
	c = tls.Server(c, e.tlsConfig)
	return e.handleConnFunc(c)
}

func (e *HttpsHijacker) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostPattern := hostPatternOf(hello.ServerName)
	vh := e.getVirtualHost(hostPattern)
	<-vh.ready
	return vh.cert, vh.err
}

func (e *HttpsHijacker) getVirtualHost(hostPattern string) *virtualHost {
	return e.VirtualHostCache.GetOrNew(hostPattern, func() interface{} {
		ready := make(chan struct{})
		vh := &virtualHost{
			ready : ready,
			deadline: time.Now().AddDate(0,0,7),
		}
		go func() {
			defer close(ready)
			cerPem, pkPem, err:= SignHost(
				hostPattern, e.RootCerPem, e.RootPkPem, vh.deadline.AddDate(0,0,7))
			if err != nil { vh.err = err ; return }
			tlsCert, err := tls.X509KeyPair(cerPem,pkPem)
			if err != nil { vh.err = err ; return }
			vh.cert = &tlsCert
		}()
		return vh
	}).(*virtualHost)
}

func (e *HttpsHijacker) putDst(clientAddr, host string) error {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	if _,exists := e.dst[clientAddr] ; exists {
		return fmt.Errorf("client address conflict")
	}
	e.dst[clientAddr] = host
	return nil
}

func (e *HttpsHijacker) removeDst(clientAddr string) {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	delete(e.dst, clientAddr)
}

func (e *HttpsHijacker) getDst(clientAddr string) (string,bool) {
	e.mtx.RLock()
	defer e.mtx.RUnlock()

	host,ok := e.dst[clientAddr]
	return host,ok
}

func (e *HttpsHijacker) serveHTTP(w http.ResponseWriter, r *http.Request) {
	dst,ok := e.getDst(r.RemoteAddr)
	if !ok {
		http.Error(w, "no destination for client address",
			http.StatusInternalServerError)
		return
	}

	r.URL.Host = dst
	r.URL.Scheme = "https"

	e.ProxyHandler.ServeHTTP(w, r)
}

func hostPatternOf(hostname string) string {
	if h,_,err := net.SplitHostPort(hostname) ; err == nil {
		hostname = h
	}
	if ip := net.ParseIP(hostname) ; ip != nil {
		return hostname
	}
	fields := strings.Split(hostname, ".")
	if len(fields) > 2 {
		fields[0] = "*"
	}
	return strings.Join(fields, ".")
}
