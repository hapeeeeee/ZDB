#include <libzdb/watchpoint.hpp>
#include <libzdb/process.hpp>

namespace {
    std::int32_t get_next_watchpoint_id() {
        static zdb::Watchpoint::id_type id = 0;
        return ++id;
    }
}

namespace zdb {
    Watchpoint::Watchpoint(Process &proc, VirtualAddr addr, StopPointMode mode, std::size_t size)
    : proc_(&proc), addr_(addr), mode_(mode), size_(size), is_enabled_(false) {
        if ((addr.addr() & (size - 1)) != 0) {
            throw std::invalid_argument("Address is not aligned to size");
        }

        id_ = get_next_watchpoint_id();
    }

    void Watchpoint::enable() {
        if (is_enabled_) {
            return;
        }
        hardware_breakpoint_id_ = proc_->set_watchpoint(id_, addr_, mode_, size_);
        is_enabled_ = true;
    }

    void Watchpoint::disable() {
        if (!is_enabled_) {
            return;
        }
        proc_->clear_hardware_breakpoint(hardware_breakpoint_id_);
        is_enabled_ = false;
    }
}
