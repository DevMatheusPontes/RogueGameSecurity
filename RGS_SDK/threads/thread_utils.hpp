#pragma once

#include <boost/thread.hpp>
#include <boost/chrono.hpp>
#include <string>

namespace rgs::sdk::threads {

namespace utils {

    // Pausa a thread atual por milissegundos
    inline void sleep_ms(int milliseconds) {
        boost::this_thread::sleep_for(boost::chrono::milliseconds(milliseconds));
    }

    // Retorna o ID da thread atual como string
    inline std::string current_thread_id() {
        std::ostringstream oss;
        oss << boost::this_thread::get_id();
        return oss.str();
    }

    // Verifica se uma thread está ativa
    inline bool is_joinable(boost::thread& t) {
        return t.joinable();
    }

}

} // namespace rgs::sdk::threads
