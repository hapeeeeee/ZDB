#include <libzdb/breakpoint.hpp>
#include <libzdb/target.hpp>
namespace {
    zdb::Breakpoint::id_type get_next_id() {
        static zdb::Breakpoint::id_type id = 0;
        return ++id;
    }
}

namespace zdb {
    Breakpoint::Breakpoint(Target& tgt, bool is_internal, bool is_hardware)
    : target_{ &tgt }, is_hardware_{ is_hardware }, is_internal_{ is_internal } 
    {
        id_ = is_internal ? -1 : get_next_id();
    }

    void Breakpoint::enable() {
        is_enabled_ = true;
        breakpoint_sites_.for_each([](auto& site) { site->enable(); });
    }

    void Breakpoint::disable() {
        is_enabled_ = false;
        breakpoint_sites_.for_each([](auto& site) { site->disable(); });
    }
}


void zdb::AddressBreakpoint::resolve() {
    if (breakpoint_sites_.empty()) {
        BreakpointSite& new_site = target_
            ->get_process()
            .create_breakpoint_site(
        this, 
                next_site_id_++, 
                address_, 
                is_hardware_, 
                is_internal_
            );

        breakpoint_sites_.push(&new_site);
        if (is_enabled_) new_site.enable();
    }
}

void zdb::FunctionBreakpoint::resolve() {
    Target::find_functions_result found_functions = target_->find_functions(function_name_);
    for (auto die : found_functions.dwarf_functions) {
        if (die.contains(DW_AT_low_pc) || die.contains(DW_AT_ranges)) {
            FileAddr addr;
            if (die.abbrev_entry()->tag == DW_TAG_inlined_subroutine) {
                addr = die.low_pc();
            }
            else { 
                // If the function was not inlined, Skip function prologue
                auto function_line = die
                    .cu()
                    ->lines()
                    .get_entry_by_address(die.low_pc());
                ++function_line;
                addr = function_line->address;
            }
            auto load_address = addr.to_virt_addr();
            if (!breakpoint_sites_.contains_address(load_address)) {
                BreakpointSite& new_site = target_
                    ->get_process()
                    .create_breakpoint_site(
                    this, 
                        next_site_id_++, 
                        load_address, 
                        is_hardware_, 
                        is_internal_
                    );
                breakpoint_sites_.push(&new_site);
                if (is_enabled_) new_site.enable();
            }
        }   
    }

    for (auto sym : found_functions.elf_functions) {
        FileAddr file_address = FileAddr{ *sym.first, sym.second->st_value };
        VirtualAddr load_address = file_address.to_virt_addr();
        if (!breakpoint_sites_.contains_address(load_address)) {
            BreakpointSite& new_site = target_
                ->get_process()
                .create_breakpoint_site(
                    this, 
                    next_site_id_++, 
                    load_address, 
                    is_hardware_, 
                    is_internal_
                );
                
            breakpoint_sites_.push(&new_site);
            if (is_enabled_) new_site.enable();
        }
    }
}

void zdb::LineBreakpoint::resolve() {
    Dwarf& dwarf = target_->get_elf().get_dwarf();
    for (auto& cu : dwarf.compile_units()) {
        auto entries = cu->lines().get_entries_by_line(file_, line_);
        for (auto entry : entries) {
            // We grab the DWARF file from the line table entry rather than using 
            // the one we got from the target: this is to support shared libraries.
            const Dwarf& dwarf = entry->address.elf()->get_dwarf();
            std::vector<DIE> stack = dwarf.inline_stack_at_file_address(entry->address);
            bool no_inline_stack = stack.size() == 1; 
            auto should_skip_prologue = no_inline_stack 
                && (stack[0].contains(DW_AT_ranges) || stack[0].contains(DW_AT_low_pc)) 
                && stack[0].low_pc() == entry->address;
            if (should_skip_prologue) {
                ++entry; 
            }
            auto load_address = entry->address.to_virt_addr();
            if (!breakpoint_sites_.contains_address(load_address)) {
                auto& new_site = target_
                    ->get_process()
                    .create_breakpoint_site(
                        this, 
                        next_site_id_++, 
                        load_address, 
                        is_hardware_, 
                        is_internal_
                    );

                breakpoint_sites_.push(&new_site);
                if (is_enabled_) new_site.enable();
            }
        }
    }
}