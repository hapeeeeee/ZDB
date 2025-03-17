#include <libzdb/breakpoint_site.hpp>

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
