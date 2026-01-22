package token

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/heliannuuthus/helios/pkg/auth/secret"
)

// KeyCache 密钥缓存管理器（优先级队列实现）
type KeyCache struct {
	loader        secret.Loader
	cache         sync.Map // clientID -> *CacheEntry
	pq            expiryQueue
	pqMu          sync.Mutex
	pqCond        *sync.Cond // 用于唤醒后台 goroutine
	ttl           time.Duration
	refreshBefore time.Duration
}

// CacheEntry 缓存条目
type CacheEntry struct {
	secrets   []*secret.SecretEntry
	expiresAt time.Time
	mu        sync.RWMutex
	refreshCh chan struct{} // 用于协调并发刷新
}

// expiryItem 优先级队列条目
type expiryItem struct {
	clientID  string
	expiresAt time.Time
	index     int // heap 索引
}

// expiryQueue 按过期时间排序的优先级队列
type expiryQueue []*expiryItem

func (pq expiryQueue) Len() int { return len(pq) }

func (pq expiryQueue) Less(i, j int) bool {
	return pq[i].expiresAt.Before(pq[j].expiresAt)
}

func (pq expiryQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *expiryQueue) Push(x any) {
	n := len(*pq)
	item := x.(*expiryItem)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *expiryQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // 避免内存泄漏
	item.index = -1 // 标记已移除
	*pq = old[0 : n-1]
	return item
}

// NewKeyCache 创建密钥缓存
func NewKeyCache(loader secret.Loader, ttl time.Duration, refreshBefore time.Duration) *KeyCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if refreshBefore <= 0 {
		refreshBefore = 1 * time.Minute
	}
	if refreshBefore >= ttl {
		refreshBefore = ttl / 2
	}

	kc := &KeyCache{
		loader:        loader,
		ttl:           ttl,
		refreshBefore: refreshBefore,
		pq:            make(expiryQueue, 0),
	}
	kc.pqCond = sync.NewCond(&kc.pqMu)
	heap.Init(&kc.pq)

	return kc
}

// Start 启动后台刷新 goroutine
func (kc *KeyCache) Start(ctx context.Context) {
	go kc.refreshLoop(ctx)
}

// refreshLoop 后台刷新循环（timer 驱动，非定时轮询）
func (kc *KeyCache) refreshLoop(ctx context.Context) {
	for {
		kc.pqMu.Lock()

		// 等待队列非空或 ctx 取消
		for kc.pq.Len() == 0 {
			// 启动一个 goroutine 监听 ctx.Done
			done := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					kc.pqMu.Lock()
					kc.pqCond.Signal()
					kc.pqMu.Unlock()
				case <-done:
				}
			}()

			kc.pqCond.Wait()
			close(done)

			if ctx.Err() != nil {
				kc.pqMu.Unlock()
				return
			}
		}

		// 获取最近到期的条目
		item := kc.pq[0]
		refreshAt := item.expiresAt.Add(-kc.refreshBefore)
		now := time.Now()

		if now.Before(refreshAt) {
			// 还没到刷新时间，设置 timer 等待
			waitDuration := refreshAt.Sub(now)
			kc.pqMu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-time.After(waitDuration):
				// 继续循环处理
			}
			continue
		}

		// 到了刷新时间，取出条目
		heap.Pop(&kc.pq)
		clientID := item.clientID
		kc.pqMu.Unlock()

		// 执行刷新
		kc.doRefresh(ctx, clientID)
	}
}

// doRefresh 执行刷新并重新入队
func (kc *KeyCache) doRefresh(ctx context.Context, clientID string) {
	// 检查缓存是否还存在
	entryVal, ok := kc.cache.Load(clientID)
	if !ok {
		return
	}

	entry := entryVal.(*CacheEntry)

	// 尝试获取刷新锁
	select {
	case entry.refreshCh <- struct{}{}:
		defer func() { <-entry.refreshCh }()
	default:
		// 已有刷新在进行，跳过
		return
	}

	// 执行加载
	secrets, err := kc.loader.Load(ctx, clientID)
	if err != nil {
		// 刷新失败，重新入队（稍后重试）
		kc.enqueue(clientID, entry.expiresAt)
		return
	}

	if len(secrets) == 0 {
		return
	}

	// 更新缓存
	newExpiresAt := time.Now().Add(kc.ttl)
	entry.mu.Lock()
	entry.secrets = secrets
	entry.expiresAt = newExpiresAt
	entry.mu.Unlock()

	// 重新入队
	kc.enqueue(clientID, newExpiresAt)
}

// enqueue 将 clientID 加入优先级队列
func (kc *KeyCache) enqueue(clientID string, expiresAt time.Time) {
	kc.pqMu.Lock()
	defer kc.pqMu.Unlock()

	heap.Push(&kc.pq, &expiryItem{
		clientID:  clientID,
		expiresAt: expiresAt,
	})
	kc.pqCond.Signal()
}

// Get 获取密钥（自动刷新）
func (kc *KeyCache) Get(ctx context.Context, clientID string) ([]*secret.SecretEntry, error) {
	if clientID == "" {
		return nil, errors.New("client_id is required")
	}

	// 尝试从缓存获取
	entryVal, ok := kc.cache.Load(clientID)
	if ok {
		entry := entryVal.(*CacheEntry)
		entry.mu.RLock()
		secrets := entry.secrets
		expiresAt := entry.expiresAt
		entry.mu.RUnlock()

		now := time.Now()
		// 如果未过期，直接返回
		if now.Before(expiresAt) {
			// 检查是否需要提前刷新（异步）
			if now.After(expiresAt.Add(-kc.refreshBefore)) {
				kc.tryAsyncRefresh(ctx, clientID, entry)
			}
			return secrets, nil
		}
	}

	// 缓存过期或不存在，同步刷新
	return kc.refresh(ctx, clientID)
}

// refresh 同步刷新密钥
func (kc *KeyCache) refresh(ctx context.Context, clientID string) ([]*secret.SecretEntry, error) {
	secrets, err := kc.loader.Load(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("load secrets: %w", err)
	}

	if len(secrets) == 0 {
		return nil, errors.New("no valid secret found")
	}

	expiresAt := time.Now().Add(kc.ttl)

	// 更新缓存
	entry := &CacheEntry{
		secrets:   secrets,
		expiresAt: expiresAt,
		refreshCh: make(chan struct{}, 1),
	}
	kc.cache.Store(clientID, entry)

	// 加入优先级队列
	kc.enqueue(clientID, expiresAt)

	return secrets, nil
}

// tryAsyncRefresh 尝试异步刷新（如果未在刷新中）
func (kc *KeyCache) tryAsyncRefresh(ctx context.Context, clientID string, entry *CacheEntry) {
	select {
	case entry.refreshCh <- struct{}{}:
		go func() {
			defer func() { <-entry.refreshCh }()

			secrets, err := kc.loader.Load(ctx, clientID)
			if err != nil || len(secrets) == 0 {
				return
			}

			newExpiresAt := time.Now().Add(kc.ttl)
			entry.mu.Lock()
			entry.secrets = secrets
			entry.expiresAt = newExpiresAt
			entry.mu.Unlock()
		}()
	default:
		// 已有刷新在进行中，跳过
	}
}

// Refresh 手动刷新密钥
func (kc *KeyCache) Refresh(ctx context.Context, clientID string) error {
	_, err := kc.refresh(ctx, clientID)
	return err
}
