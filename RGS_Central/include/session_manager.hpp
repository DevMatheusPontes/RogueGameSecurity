#pragma once

#include "../../RGS_SDK/network/session.hpp"
#include <memory>
#include <mutex>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>

namespace rgs::central {

    using SessionPtr = std::shared_ptr<sdk::network::Session>;

    // Tags for multi-index container
    struct tag_id {};
    struct tag_ptr {};

    class SessionManager {
    public:
        SessionManager() = default;

        void add(const SessionPtr& session);
        void remove(const SessionPtr& session);
        SessionPtr find(uint64_t sessionId);
        size_t count() const;

    private:
        using SessionContainer = boost::multi_index::multi_index_container<
            SessionPtr,
            boost::multi_index::indexed_by<
                boost::multi_index::ordered_unique<boost::multi_index::tag<tag_ptr>, boost::multi_index::identity<SessionPtr>>,
                boost::multi_index::ordered_unique<boost::multi_index::tag<tag_id>, boost::multi_index::const_mem_fun<sdk::network::Session, uint64_t, &sdk::network::Session::getId>>
            >
        >;

        mutable std::mutex m_mutex;
        SessionContainer m_sessions;
        uint64_t m_nextSessionId = 1;
    };

} // namespace rgs::central
