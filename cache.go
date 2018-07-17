package httpsproxy

import "sync"

type Cache interface {
	// newFunc不应该堵塞。
	// 如果新实例需要较长时间的初始化，应该异步执行，并有类似WaitForReady的接口等待初始化完成。
	// 如果newFunc返回的对象实现Finalizer，则被Cache实现丢弃时调用Finalize。
	// 如果newFunc返回的对象实现Expirer，则以后GetOrNew检查Expired()，返回true则重新调用newFunc。
	GetOrNew(key interface{}, newFunc func() interface{}) interface{}
}

type Finalizer interface {
	Finalize()
}

type Expirer interface{
	Expired() bool
}

func NewLRUCache(capacity int) Cache {
	return &LRUCache{
		capacity : capacity,
		items : map[interface{}]*lruCacheItem{},
	}
}

type LRUCache struct {
	mtx sync.Mutex
	capacity int
	count int
	front *lruCacheItem
	last *lruCacheItem
	items map[interface{}]*lruCacheItem
}

type lruCacheItem struct {
	key interface{}
	val interface{}
	prev *lruCacheItem
	next *lruCacheItem
}

func (c *LRUCache) GetOrNew(key interface{}, newFunc func() interface{}) interface{} {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	if item,ok := c.items[key]; ok {
		if e,ok := item.val.(Expirer); ok && e.Expired() {
			if f, ok := item.val.(Finalizer); ok {
				f.Finalize()
			}
			item.val = newFunc()
		}
		c.bringToFront(item)
		return item.val
	}
	val := newFunc()
	c.add(key, val)
	return val
}

func (c *LRUCache) Clear() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	for _, item := range c.items {
		if f, ok := item.val.(Finalizer); ok {
			f.Finalize()
		}
	}

	c.front = nil
	c.last = nil
	c.items = map[interface{}]*lruCacheItem{}
}

func (c *LRUCache) add(key, val interface{}) {
	item := &lruCacheItem{
		key : key,
		val : val,
		next : c.front,
	}
	c.items[key] = item
	if c.front != nil {
		c.front.prev = item
	} else {
		c.last = item
	}
	c.front = item
	c.count++
	if c.count > c.capacity {
		c.dropLast()
	}
}

func (c *LRUCache) bringToFront(item *lruCacheItem) {
	if c.front == item { return }
	item.prev.next = item.next
	if item.next != nil {
		item.next.prev = item.prev
	}
	item.prev = nil
	item.next = c.front
	c.front.prev = item
	c.front = item
}

func (c *LRUCache) dropLast() {
	item := c.last
	if item == nil { return }

	if f, ok := item.val.(Finalizer); ok {
		f.Finalize()
	}

	if item.prev != nil {
		item.prev.next = nil
	}
	c.last = item.prev
	delete(c.items, item.key)
	c.count--
}
