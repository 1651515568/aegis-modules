package vulnscan

import "sync"

// ssePayload 是 SSE 推送的单条消息结构。
type ssePayload struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// eventBus 是单播/多播 SSE 事件总线，支持多个并发订阅者。
type eventBus struct {
	mu      sync.Mutex
	clients map[chan ssePayload]struct{}
}

func newEventBus() *eventBus {
	return &eventBus{clients: make(map[chan ssePayload]struct{})}
}

// Subscribe 注册一个订阅者，返回一个带缓冲的事件 channel。
func (eb *eventBus) Subscribe() chan ssePayload {
	ch := make(chan ssePayload, 64)
	eb.mu.Lock()
	eb.clients[ch] = struct{}{}
	eb.mu.Unlock()
	return ch
}

// Unsubscribe 注销订阅者并关闭其 channel。
func (eb *eventBus) Unsubscribe(ch chan ssePayload) {
	eb.mu.Lock()
	delete(eb.clients, ch)
	eb.mu.Unlock()
	close(ch)
}

// Publish 向所有订阅者广播事件；慢客户端直接丢包，不阻塞发布者。
func (eb *eventBus) Publish(evtType string, data interface{}) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	p := ssePayload{Type: evtType, Data: data}
	for ch := range eb.clients {
		select {
		case ch <- p:
		default:
		}
	}
}
