#pragma once

namespace rgs::sdk::hooks {

    class ReentryGuard {
    public:
        ReentryGuard(bool& flag) : m_flag(flag) {
            if (m_flag) {
                m_locked = false;
            } else {
                m_flag = true;
                m_locked = true;
            }
        }

        ~ReentryGuard() {
            if (m_locked) {
                m_flag = false;
            }
        }

        operator bool() const {
            return m_locked;
        }

    private:
        bool& m_flag;
        bool m_locked;
    };

    // Usage: In your hook function:
    // static thread_local bool guard_flag = false;
    // if (!ReentryGuard(guard_flag)) return;

    #define RGS_REENTRY_GUARD() \
        static thread_local bool guard_flag = false; \
        if (!rgs::sdk::hooks::ReentryGuard(guard_flag)) return

} // namespace rgs::sdk::hooks
