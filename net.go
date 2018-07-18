package httpsproxy

import (
	"net"
	"sync"
	"fmt"
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

type Tunneler interface{
	// Tunnel接管连接c，该连接已请求访问主机hostname。
	// Tunnel返会后，调用者不应再操作c。
	Tunnel(c net.Conn, hostname string) error
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
