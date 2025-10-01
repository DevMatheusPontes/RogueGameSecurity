#pragma once

#include <thread>
#include <vector>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace rgs::threading {

// Pool genérico de threads para tarefas curtas.
class ThreadPool {
public:
    explicit ThreadPool(std::size_t threads);
    ~ThreadPool();

    // Enfileira uma tarefa.
    void enqueue(std::function<void()> task);

    // Para o pool e aguarda threads.
    void shutdown();

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stop_;
};

} // namespace rgs::threading