# HTTP/HTTPS 代理

这是一个用Golang开发的 HTTP/HTTPS 代理模块，可以使用自签发证书解密HTTPS连接。

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

	all_proxy=localhost:3128 curl -k https://www.baidu.com

curl 的 -k 参数可以忽略证书认证。如果需要信任根证书，这样获取根证书：

	curl localhost:3128/rootca

## 应用

在你的项目中可能有更多的不同需求：

- 使用手工签发的根证书；
- 设置服务的超时等参数；
- 分发HTTP/HTTPS请求；
- 采集日志；
- 显示请求内容。

本项目都可以作为基础。

ProxyServer和HttpsExtractor是本项目的核心组件，使用方式请参考example.go。
以上示例使用的SimpleListenAndServe就在example.go里。