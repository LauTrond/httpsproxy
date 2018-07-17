package httpsproxy

import (
	"net"
	"sync"
)

type CloseNotifyConn struct {
	net.Conn

	initOnce, closeOnce sync.Once
	closed chan struct{}
}

func (c *CloseNotifyConn) init() {
	c.initOnce.Do(func(){
		c.closed = make(chan struct{})
	})
}

func (c *CloseNotifyConn) Close() error {
	c.init()
	err := c.Conn.Close()
	c.closeOnce.Do(func(){
		close(c.closed)
	})
	return err
}

//返回一个channel，当Close()被调用时被关闭
func (c *CloseNotifyConn) GetCloseChan() <-chan struct{} {
	c.init()
	return c.closed
}

func HookCloseConn(c net.Conn, callback func()) net.Conn {
	cnc,ok := c.(*CloseNotifyConn)
	if !ok {
		cnc = &CloseNotifyConn{ Conn : c }
	}

	chanClosed := cnc.GetCloseChan()
	go func() {
		<-chanClosed
		callback()
	}()

	return cnc
}

type TunnelHandler interface{
	HandleTunnel(c net.Conn, hostname string) error
}
