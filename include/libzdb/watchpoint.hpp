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

            std::uint64_t data() const { return data_; }
            std::uint64_t previous_data() const { return previous_data_; }
            void update_data();

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

            std::uint64_t data_;
            std::uint64_t previous_data_;
    };
}
#endif // LIBZDB_WATCHPOINT_HPP