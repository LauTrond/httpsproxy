package httpsproxy

import (
	"context"
	"net/http"
	"time"
)

// 打开一个HTTP/HTTPS代理服务。
// 所有HTTPS访问都会被截取，使用临时生成的根证书，客户端需要信任根证书或忽略证书认证。
// HTTP访问路径/rootca可以下载根证书。
func SimpleListenAndServe(addr string) error {
	rootCerPem, rootKeyPem, err := SignRoot(time.Now().AddDate(1, 0, 0))
	if err != nil { return err }

	http.Handle("/rootca", &FileHandler{
		ContentType : "text/plain",
		Data : rootCerPem,
	})

	return ListenAndServe(addr, rootCerPem, rootKeyPem)
}

func ListenAndServe(addr string, rootCerPem, rootKeyPem []byte) error {
	//ProxyServer是代理服务，NewHttpsHijacker创建一个默认的HTTPS拦截实例。
	//注意这里把ProxyServer.ServeHttpProxy赋值给HttpsHijacker.Handler，也把HttpsHijacker赋值给TunnelHandler。
	proxyServer := &ProxyServer{
		LocalHandler: http.DefaultServeMux,
	}
	hijacker := NewHttpsHijacker(
		http.HandlerFunc(proxyServer.ServeHttpProxy),
		rootCerPem, rootKeyPem,
	)
	proxyServer.TunnelHandler = hijacker

	//HttpsHijacker内部包含一个的http.Server，需要调用Serve来启动、开始处理解密后的HTTPS连接。
	go hijacker.Serve() //直到调用Shutdown，Serve是不会返回的

	err := http.ListenAndServe(addr, proxyServer)

	ctxShutdown,cancelCtx := context.WithTimeout(context.Background(), time.Second)
	defer cancelCtx()
	hijacker.Shutdown(ctxShutdown)

	return err
}
