package httpsproxy

import (
	"strings"
	"log"
	"net/http"
	"time"
	"io"
	"fmt"
)

type ProxyServer struct {
	//处理CONNECT方法时发起连接函数
	//nil则禁用CONNECT方法
	TunnelHandler TunnelHandler

	//处理http请求
	//nil则使用http.DefaultTransport
	Transport http.RoundTripper

	//响应代理请求（GET http://... 或 CONNECT host:port）之外的请求
	//nil则对这些请求返回404 NotFound
	LocalHandler http.Handler
}

func (s *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("Proxy-Authorization")

	if r.Method == "CONNECT" {
		if s.TunnelHandler == nil {
			http.Error(w, "CONNECT method not allowed",
				http.StatusMethodNotAllowed)
		} else {
			s.handleTunneling(w, r)
		}
	} else if r.URL.Host == "" || strings.ToLower(r.URL.Host) == "proxy" {
		if s.LocalHandler != nil {
			s.LocalHandler.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	} else {
		s.ServeHttpProxy(w, r)
	}
}

func (s *ProxyServer) ServeHttpProxy(w http.ResponseWriter, r *http.Request) {
	rt := s.Transport
	if rt == nil { rt = http.DefaultTransport }

	r.Header.Set("Connection", "keep-alive")
	r.Close = false

	startTime := time.Now()
	resp,err := rt.RoundTrip(r)
	if resp != nil { defer resp.Body.Close() }

	status := "-"
	errmsg := "-"

	if HasClosed(r.Context().Done()) {
		status = "901 Canceled"
		errmsg = r.Context().Err().Error()
		http.Error(w, errmsg, http.StatusInternalServerError)

		//因为Golang标准库的bug，在某些情况下，连接的ctx已经被cancel，但连接一直被重用。
		//这里Hijack并强行关闭连接。
		if h,ok := w.(http.Hijacker) ; ok {
			if conn,_,_ := h.Hijack() ; conn != nil {
				conn.Close()
			}
		}
	} else if err != nil {
		status = "900 Network Error"
		errmsg = err.Error()
		http.Error(w, err.Error(), http.StatusBadGateway)
	} else {
		status = fmt.Sprintf("%02d %s",
			resp.StatusCode,http.StatusText(resp.StatusCode))

		bodyErr := pipeResponse(w, resp)
		if bodyErr != nil {
			errmsg = bodyErr.Error()
		}
	}

	dur := time.Since(startTime) / time.Millisecond
	status = strings.Replace(status, "\"", "'", -1)
	log.Printf("%s %s \"%s\" \"%s\" %dms",
		r.Method, r.URL.String(), status, errmsg, dur)
}

func (s *ProxyServer) handleTunneling(w http.ResponseWriter, r *http.Request) {
	hijacker,ok :=  w.(http.Hijacker)
	if !ok {
		http.Error(w, "unsupported", http.StatusInternalServerError)
		log.Println(r.Method, r.RequestURI, "Hijack:", "unsupported")
		return
	}

	w.WriteHeader(http.StatusOK)
	conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(r.Method, r.RequestURI, "Hijack:", err.Error())
		return
	}
	conn.SetDeadline(time.Time{})

	err = s.TunnelHandler.HandleTunnel(conn, r.RequestURI)
	if err != nil {
		conn.Close()
		log.Println(r.Method, r.RequestURI, "HandleTunnel:", err.Error())
		return
	}

	log.Println(r.Method, r.RequestURI, "ok")
}

func pipeResponse(w http.ResponseWriter, resp *http.Response) error {
	CopyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	//传输HTTP body，这一行代码可能贡献了本程序90%的CPU使用
	_,bodyErr := io.Copy(w, resp.Body)
	return bodyErr
}
