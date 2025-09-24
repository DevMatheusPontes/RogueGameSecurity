#include "threads/thread_utils.hpp"

using namespace rgs::sdk::threads::utils;

sleep_ms(500); // pausa por 500ms

std::string id = current_thread_id(); // ID da thread atual

if (is_joinable(my_thread)) {
    my_thread.join();
}
