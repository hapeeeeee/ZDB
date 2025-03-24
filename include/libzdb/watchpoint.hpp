#ifndef LIBZDB_WATCHPOINT_HPP
#define LIBZDB_WATCHPOINT_HPP

#include <libzdb/types.hpp>

namespace zdb {
    class Process;

    class Watchpoint {
        public:
            using id_type = std::int32_t;

            Watchpoint() = delete;
            Watchpoint(const Watchpoint &) = delete;
            Watchpoint &operator=(const Watchpoint &) = delete;
            Watchpoint(Watchpoint &&) = delete;
            Watchpoint &operator=(Watchpoint &&) = delete;

            id_type id() const { return id_; }
            VirtualAddr address() const { return addr_; }
            std::size_t size() const { return size_; }
            bool is_enabled() const { return is_enabled_; }
            StopPointMode mode() const { return mode_; }
            
            bool at_address(VirtualAddr address) const {
                return addr_ == address;
            }

            bool in_range(VirtualAddr low, VirtualAddr high) const {
                return low <= addr_ && addr_ < high;
            }

            void enable();
            void disable(); 

        private:
            friend class Process;
            Watchpoint(Process &proc, VirtualAddr addr, StopPointMode mode, std::size_t size);

            Process *proc_;
            id_type id_;
            VirtualAddr addr_;
            StopPointMode mode_;
            std::size_t size_;
            bool is_enabled_;
            int hardware_breakpoint_id_ = -1;
    };
}
#endif // LIBZDB_WATCHPOINT_HPP