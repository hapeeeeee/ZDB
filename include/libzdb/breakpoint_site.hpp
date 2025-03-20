
#ifndef LIBZDB_BREAKPOINT_SITE_HPP
#define LIBZDB_BREAKPOINT_SITE_HPP

#include <cstdint>
#include <libzdb/types.hpp>

namespace zdb {
class Process;

    class BreakpointSite {
      public:
        using id_type = std::int32_t;

        BreakpointSite() = delete;
        BreakpointSite(const BreakpointSite&) = delete;
        BreakpointSite(BreakpointSite&&) = delete;
        BreakpointSite& operator=(const BreakpointSite&) = delete;
        BreakpointSite& operator=(BreakpointSite&&) = delete;

        id_type id() const { return id_; }
        VirtualAddr address() const { return address_; }
        std::byte saved_data() const { return saved_data_; }

        void enable();
        void disable();
        bool is_enabled() const { return is_enabled_; }
        bool at_address(VirtualAddr address) const {
            return address_ == address;
        }
        bool in_range(VirtualAddr low, VirtualAddr high) const {
            return low <= address_ && address_ < high;
        }

      private:
        id_type id_;
        bool is_enabled_;
        VirtualAddr address_;
        Process* proc_;
        std::byte saved_data_;
        
        friend Process;
        BreakpointSite(Process& proc, VirtualAddr address);
    };

    } // namespace libzdb

#endif // LIBZDB_BREAKPOINT_SITE_HPP
