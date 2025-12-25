package utils

import (
	"context"
	"sync"
)

// WorkerPool manages a pool of concurrent workers
type WorkerPool struct {
	workers int
	jobs    chan interface{}
	results chan interface{}
	wg      sync.WaitGroup
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workers int, bufferSize int) *WorkerPool {
	if workers <= 0 {
		workers = 10
	}
	if bufferSize <= 0 {
		bufferSize = workers * 2
	}

	return &WorkerPool{
		workers: workers,
		jobs:    make(chan interface{}, bufferSize),
		results: make(chan interface{}, bufferSize),
	}
}

// WorkerFunc is the function signature for worker processing
type WorkerFunc func(ctx context.Context, job interface{}) interface{}

// Start begins the worker pool with the given worker function
func (wp *WorkerPool) Start(ctx context.Context, workerFn WorkerFunc) {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go func() {
			defer wp.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-wp.jobs:
					if !ok {
						return
					}
					result := workerFn(ctx, job)
					if result != nil {
						select {
						case wp.results <- result:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}
}

// Submit adds a job to the pool
func (wp *WorkerPool) Submit(job interface{}) {
	wp.jobs <- job
}

// Close closes the job channel and waits for workers to finish
func (wp *WorkerPool) Close() {
	close(wp.jobs)
	wp.wg.Wait()
	close(wp.results)
}

// Results returns the results channel
func (wp *WorkerPool) Results() <-chan interface{} {
	return wp.results
}

// Semaphore provides a simple semaphore for limiting concurrency
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore creates a new semaphore with n slots
func NewSemaphore(n int) *Semaphore {
	return &Semaphore{
		ch: make(chan struct{}, n),
	}
}

// Acquire acquires a slot
func (s *Semaphore) Acquire() {
	s.ch <- struct{}{}
}

// Release releases a slot
func (s *Semaphore) Release() {
	<-s.ch
}

// TryAcquire tries to acquire a slot without blocking
func (s *Semaphore) TryAcquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// WaitGroup is a wrapper around sync.WaitGroup with additional features
type WaitGroup struct {
	wg      sync.WaitGroup
	count   int
	countMu sync.Mutex
}

// Add adds to the wait group counter
func (w *WaitGroup) Add(delta int) {
	w.countMu.Lock()
	w.count += delta
	w.countMu.Unlock()
	w.wg.Add(delta)
}

// Done decrements the wait group counter
func (w *WaitGroup) Done() {
	w.countMu.Lock()
	w.count--
	w.countMu.Unlock()
	w.wg.Done()
}

// Wait waits for all goroutines to finish
func (w *WaitGroup) Wait() {
	w.wg.Wait()
}

// Count returns the current count
func (w *WaitGroup) Count() int {
	w.countMu.Lock()
	defer w.countMu.Unlock()
	return w.count
}

// FanOut executes functions concurrently and waits for all to complete
func FanOut(ctx context.Context, fns ...func(context.Context) error) error {
	errs := make(chan error, len(fns))
	var wg sync.WaitGroup

	for _, fn := range fns {
		wg.Add(1)
		go func(f func(context.Context) error) {
			defer wg.Done()
			if err := f(ctx); err != nil {
				select {
				case errs <- err:
				default:
				}
			}
		}(fn)
	}

	wg.Wait()
	close(errs)

	// Return first error if any
	for err := range errs {
		if err != nil {
			return err
		}
	}

	return nil
}

// ParallelMap applies fn to each item in parallel
func ParallelMap[T any, R any](ctx context.Context, items []T, workers int, fn func(context.Context, T) (R, error)) ([]R, error) {
	if workers <= 0 {
		workers = len(items)
	}

	results := make([]R, len(items))
	errs := make(chan error, 1)
	sem := NewSemaphore(workers)
	var wg sync.WaitGroup

	for i, item := range items {
		wg.Add(1)
		go func(idx int, it T) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			sem.Acquire()
			defer sem.Release()

			result, err := fn(ctx, it)
			if err != nil {
				select {
				case errs <- err:
				default:
				}
				return
			}
			results[idx] = result
		}(i, item)
	}

	wg.Wait()

	select {
	case err := <-errs:
		return nil, err
	default:
		return results, nil
	}
}
