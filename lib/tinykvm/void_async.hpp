#pragma once
#include <functional>
#include <future>

template<class Function, class... Args>
inline void async_wrapper(Function&& f, Args&&... args, std::future<void>& future,
                   std::future<void>&& is_valid, std::promise<void>&& is_moved) {
    is_valid.wait(); // Wait until the return value of std::async is written to "future"
    auto our_future = std::move(future); // Move "future" to a local variable
    is_moved.set_value(); // Only now we can leave void_async in the main thread

    // This is also used by std::async so that member function pointers work transparently
    auto functor = std::bind(f, std::forward<Args>(args)...);
    functor();
}

template<class Function, class... Args>
inline void void_async(Function&& f, Args&&... args)
{
    std::future<void> future;
    // This is for our synchronization of moving "future" between threads
    std::promise<void> valid;
    std::promise<void> is_moved;
    auto valid_future = valid.get_future();
    auto moved_future = is_moved.get_future();

    // Here we pass "future" as a reference, so that async_wrapper
    // can later work with std::async's return value
    future = std::async(
        async_wrapper<Function, Args...>,
        std::forward<Function>(f), std::forward<Args>(args)...,
        std::ref(future), std::move(valid_future), std::move(is_moved)
    );
    valid.set_value(); // Unblock async_wrapper waiting for "future" to become valid
    moved_future.wait(); // Wait for "future" to actually be moved
}
