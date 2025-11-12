#include <libzdb/breakpoint_site.hpp>
#include <sys/ptrace.h>
#include <libzdb/process.hpp>

namespace {
    zdb::BreakpointSite::id_type get_next_id() {
        static zdb::BreakpointSite::id_type id = 0;
        return ++id;
    }
}

zdb::BreakpointSite::BreakpointSite(
    zdb::Process& proc, 
    zdb::VirtualAddr address, 
    bool is_internal, 
    bool is_hardware
): is_internal_(is_internal),  is_hardware_(is_hardware), 
    proc_(&proc), address_(address), is_enabled_(false), saved_data_{}
{
    id_ = is_internal_ ? -1 : get_next_id();
}

zdb::BreakpointSite::BreakpointSite(
    zdb::Process& proc, 
    zdb::Breakpoint* parent,
    id_type id, 
    zdb::VirtualAddr address, 
    bool is_internal, 
    bool is_hardware
)
    : parent_(parent), id_(id), is_internal_(is_internal),  is_hardware_(is_hardware), 
    proc_(&proc), address_(address), is_enabled_(false), saved_data_{}
{}

void zdb::BreakpointSite::enable() {
    if (is_enabled_) {
        return;
    }

    if (is_hardware_) {
        hardware_register_id_ = proc_->set_hardware_breakpoint(id_, address_);
    } else {
        errno = 0;
        std::uint64_t data = ptrace(PTRACE_PEEKDATA, proc_->pid(), address_.addr(), nullptr);
        if (errno != 0) {
            zdb::Error::send("Failed to peek data at address " + std::to_string(address_.addr()));
        }
        saved_data_ = static_cast<std::byte>(data & 0xff);
        std::uint64_t data_with_int3 = (data & ~0x00000000000000ff) | 0x00000000000000cc;
        if (ptrace(PTRACE_POKEDATA, proc_->pid(), address_.addr(), data_with_int3) < 0) {
            zdb::Error::send("Failed to enable breakpoint site at address " + std::to_string(address_.addr()));
        }
    }

    is_enabled_ = true;
}

void zdb::BreakpointSite::disable() {
    if (!is_enabled_) {
        return;
    }

    if (is_hardware_) {
        proc_->clear_hardware_stoppoint(hardware_register_id_);
        hardware_register_id_ = -1;
    } else {
        errno = 0;
        std::uint64_t data = ptrace(PTRACE_PEEKDATA, proc_->pid(), address_.addr(), nullptr);
        if (errno != 0) {
            zdb::Error::send("Failed to peek data at address " + std::to_string(address_.addr()));
        }
    
        std::uint64_t data_with_saved_data = (data & ~0x00000000000000ff) | static_cast<std::uint8_t>(saved_data_);
        if (ptrace(PTRACE_POKEDATA, proc_->pid(), address_.addr(), data_with_saved_data) < 0) {
            zdb::Error::send("Failed to disable breakpoint site at address " + std::to_string(address_.addr()));
        }
    }
   
    is_enabled_ = false;
}
