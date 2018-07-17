# HTTPS解密代理

轻量级的HTTPS解密代理，传入一个监听地址就解决所有问题，包括生成根证书。

Lightweight HTTPS hijacking proxy.

Golang 1.10+

## 安装：

	go get github.com/LauTrond/httpsproxy

## 示例

	package main

	import (
		"log"
		"github.com/LauTrond/httpsproxy"
	)

	func main() {
		log.Fatal(httpsproxy.SimpleListenAndServe("localhost:3128"))
	}

上面这个简单示例每次都会签发新的TLS证书。启动示例后，用curl测试：

	all_proxy=localhost:3128 curl -k http://news.baidu.com/guonei

注意请求地址中的路径/guonei出现在日志中，如果没有解密是不可能显示的。

curl 的 -k 参数可以忽略证书认证。如果要让客户端手动信任根证书，可以这样获取根证书：

	curl localhost:3128/rootca

## 应用

ProxyServer和HttpsExtractor是本项目的核心组件，
example.go含有基本的使用方法，
以上示例使用的SimpleListenAndServe就在example.go里。
你的项目中可能有更多的不同需求：

- 使用手工签发的根证书；
- 设置服务的超时等参数；
- 分发HTTP/HTTPS请求；
- 采集日志；
- 显示请求内容。

都可以以本项目为基础，ProxyServer和HttpsExtractor设计有多个可选参数。

