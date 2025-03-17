#include <libzdb/breakpoint_site.hpp>
#include <sys/ptrace.h>
#include <libzdb/process.hpp>

namespace {
    zdb::BreakpointSite::id_type get_next_id() {
        static zdb::BreakpointSite::id_type id = 0;
        return ++id;
    }
}

zdb::BreakpointSite::BreakpointSite(zdb::Process& proc, zdb::VirtualAddr address)
    : proc_(&proc), address_(address), is_enabled_(false), saved_data_{}
{
    id_ = get_next_id();
}

void zdb::BreakpointSite::enable() {
    if (is_enabled_) {
        return;
    }
    errno = 0;
    std::uint64_t data = ptrace(PTRACE_PEEKDATA, proc_->pid(), address_.addr(), nullptr);
    if (errno != 0) {
        zdb::Error::send("Failed to peek data at address " + std::to_string(address_.addr()));
    }
    saved_data_ = static_cast<std::byte>(data & 0xff);
    std::uint64_t data_with_int3 = (data & ~0x00000000000000ff) | 0x00000000000000cc;
    if (ptrace(PTRACE_POKEDATA, proc_->pid(), address_.addr(), data_with_int3) < 0) {
        zdb::Error::send("Failed to set breakpoint site at address " + std::to_string(address_.addr()));
    }

    is_enabled_ = true;
}
