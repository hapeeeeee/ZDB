#include <libzdb/target.hpp>
#include <libzdb/elf.hpp>
#include <optional>
#include <libzdb/disassembler.hpp>
#include <cxxabi.h>
#include <fstream>

namespace {
    std::unique_ptr<zdb::ELF> create_loaded_elf(
        const zdb::Process &process, 
        const std::filesystem::path &path
    ) {
        auto auxv = process.get_auxv();
        std::unique_ptr<zdb::ELF> elf = std::make_unique<zdb::ELF>(path);
        elf->notify_loaded(zdb::VirtualAddr(
            // load_bias_ = 
            //  actual memory address of the program entry point 
            //  - load address in elf phisical elf file
            auxv[AT_ENTRY] - elf->get_elf_header().e_entry
        ));

        return elf;
    }

    std::filesystem::path dump_vdso(const zdb::Process& proc, zdb::VirtualAddr address) {
        char tmp_dir[] = "/tmp/sdb-XXXXXX";
        mkdtemp(tmp_dir);
        std::filesystem::path vdso_dump_path = std::filesystem::path(tmp_dir) / "linux-vdso.so.1";
        std::ofstream vdso_dump(vdso_dump_path, std::ios::binary);
        Elf64_Ehdr vdso_header = proc.read_memory_as<Elf64_Ehdr>(address);
        auto vdso_size = 
            vdso_header.e_shoff + vdso_header.e_shentsize * vdso_header.e_shnum;
        std::vector<std::byte> vdso_bytes = proc.read_memory(address, vdso_size);
        vdso_dump.write(reinterpret_cast<const char*>(vdso_bytes.data()), vdso_bytes.size());
        return vdso_dump_path;
    }
}

std::unique_ptr<zdb::Target> zdb::Target::launch(
    std::filesystem::path path,
    std::optional<int> stdout_fd
) {
    auto process = Process::launch(path, true, stdout_fd);
    auto elf = create_loaded_elf(*process, path);
    auto target = std::unique_ptr<Target>(
        new Target(std::move(process), std::move(elf))
    );
    target->process_->set_target(target.get());
    auto entry_point = VirtualAddr{ target->get_process().get_auxv()[AT_ENTRY] };
    auto& entry_bp = target->create_address_breakpoint(entry_point, true, false);
    entry_bp.install_hit_handler([tgt = target.get()] {
        tgt->resolve_dynamic_linker_rendezvous();
        return true;
    });
    entry_bp.enable();
    return target;
}

std::unique_ptr<zdb::Target> zdb::Target::attach(pid_t pid) {
    // We need a way to find the ELF file associated with a given PID.
    // The /proc/<pid>/exe file is a symbolic link to the executable 
    // for the given process.
    auto elf_path = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto proc = Process::attach(pid);
    auto obj = create_loaded_elf(*proc, elf_path);
    auto target = std::unique_ptr<Target>(
        new Target(std::move(proc), std::move(obj))
    );
    target->process_->set_target(target.get());
    target->resolve_dynamic_linker_rendezvous();
    return target;
}

zdb::FileAddr zdb::Target::get_pc_file_address(std::optional<pid_t> otid) const {
    return process_->get_pc(otid).to_file_addr(elves_);
}

zdb::LineTable::iterator zdb::Target::line_entry_at_pc(std::optional<pid_t> otid) const {
    FileAddr pc = get_pc_file_address(otid);
    if (!pc.elf()) return LineTable::iterator();
    const CompileUnit* cu = pc.elf()->get_dwarf().compile_unit_containing_address(pc);
    if (!cu) return LineTable::iterator();
    return cu->lines().get_entry_by_address(pc);
}

std::vector<zdb::LineTable::iterator> zdb::Target::get_line_entries_by_line(
    std::filesystem::path path, 
    std::size_t line
) const {
    std::vector<zdb::LineTable::iterator> entries;
    elves_.for_each([&](zdb::ELF& elf) {
        for (auto& cu : elf.get_dwarf().compile_units()) {
            auto new_entries = cu->lines().get_entries_by_line(path, line);
            entries.insert(entries.end(), new_entries.begin(), new_entries.end());
        }
    });
    return entries;
}

zdb::StopReason zdb::Target::run_until_address(VirtualAddr address, std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    BreakpointSite* breakpoint_to_remove = nullptr;
    if (!process_->breakpoint_sites().contains_address(address)) {
        breakpoint_to_remove = &process_->create_breakpoint_site(
            address, 
            true,
            false
        );
        breakpoint_to_remove->enable();
    }
    process_->resume(tid);
    auto reason = process_->wait_on_signal(tid);
    if (reason.is_breakpoint() && process_->get_pc(tid) == address) {
        reason.trap_type = TrapType::SignalStep;
    }
    if (breakpoint_to_remove) {
        process_->breakpoint_sites().remove_by_address(breakpoint_to_remove->address());
    }
    threads_.at(tid).state->reason = reason;
    return reason;
}

void zdb::Target::notify_stop(const StopReason& reason) {
    threads_.at(reason.tid).frames.unwind();
}

void zdb::Target::notify_thread_lifecycle_event(const zdb::StopReason& reason) {
    auto tid = reason.tid;
    if (reason.reason == ProcessState::Stopped) {
        auto& state = process_->thread_states()[tid];
        threads_.emplace(tid, Thread{ &state, Stack{this, tid} });
    }
    else {
        threads_.erase(tid);
    }
}

zdb::StopReason zdb::Target::step_in(std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    auto& stack = get_stack(tid);
    auto& thread = threads_.at(tid);

    if (stack.inline_height() > 0) {
        stack.simulate_inlined_step_in();
        StopReason reason(tid, ProcessState::Stopped, SIGTRAP, TrapType::SignalStep);
        thread.state->reason = reason;
        return reason;
    }

    auto orig_line = line_entry_at_pc(tid);
    do {
        auto reason = process_->step(tid);
        if (!reason.is_step()) {
            // Stopped at a breakpoint or terminated completely
            thread.state->reason = reason;
            return reason;
        }
    } while ((line_entry_at_pc(tid) == orig_line || line_entry_at_pc(tid)->end_sequence)
            && line_entry_at_pc(tid) != LineTable::iterator{});

    // we may still need to step over the function prologue
    // if we’ve entered a new function
    auto pc = get_pc_file_address(tid);
    if (pc.elf() != nullptr) {
        auto& dwarf = pc.elf()->get_dwarf();
        auto func = dwarf.function_containing_address(pc);
        if (func && func->low_pc() == pc) {
            auto line = line_entry_at_pc(tid);
            if (line != LineTable::iterator{}) {
                ++line;
                return run_until_address(line->address.to_virt_addr(), tid);
            }
        }
    }

    StopReason reason(tid, ProcessState::Stopped, SIGTRAP, TrapType::SignalStep, std::nullopt);
    thread.state->reason = reason;
    return reason;
}

zdb::StopReason zdb::Target::step_over(std::optional<pid_t> otid) {
    auto tid = otid.value_or(process_->current_thread());
    auto& stack = get_stack(tid);
    auto& thread = threads_.at(tid);

    LineTable::iterator orig_line = line_entry_at_pc(tid);
    Disassembler disas(*process_);

    zdb::StopReason reason;
    do {
        auto inline_stack = stack.inline_stack_at_pc();
        auto at_start_of_inline_frame = stack.inline_height() > 0;
        if (at_start_of_inline_frame) {
            // This implementation of skipping inline frames will work in most cases
            // with unoptimized code, but it’s not necessarily the case that control flow
            // will hit the instruction directly after the inlined block after completing its
            // execution. Production debuggers will look for any branch instructions in
            // the inlined block, and if they find any, will step through the inlined block by
            // putting breakpoints at each branch instruction until the program makes it
            // out of the program counter ranges for the inlined function. This approach
            // is significantly more complex, so I’ve opted for the simpler solution here.
            DIE frame_to_skip = inline_stack[inline_stack.size() - stack.inline_height()];
            VirtualAddr return_address = frame_to_skip.high_pc().to_virt_addr();
            reason = run_until_address(return_address, tid);
            if (!reason.is_step() || process_->get_pc(tid) != return_address) {
                thread.state->reason = reason;
                return reason;
            }
        }
        else if (
            auto instructions = disas.disassemble(2, process_->get_pc(tid));
            instructions[0].text.rfind("call") == 0
        ) {
            reason = run_until_address(instructions[1].address, tid);
            if (!reason.is_step() || process_->get_pc(tid) != instructions[1].address) {
                thread.state->reason = reason;
                return reason;
            }
        }
        else {
            reason = process_->step(tid);
            if (!reason.is_step()) {
                thread.state->reason = reason;
                return reason;
            }
        }
    } while ((line_entry_at_pc(tid) == orig_line || line_entry_at_pc(tid)->end_sequence)
        && line_entry_at_pc(tid) != LineTable::iterator{});
    thread.state->reason = reason;
    return reason;
}

zdb::StopReason zdb::Target::step_out(std::optional<pid_t> otid) {
    // Recall the simplified x64 stack we discussed in Chapter 2, in which each
    // stack frame contains the return address of the current function. However,
    // while the program is running, it’s not clear how to locate exactly where on
    // the stack the return address is. We can figure this out in two main ways.
    // The more robust way of determining this location is to parse the DWARF
    // information for details about the call frame. While parsing the DWARF is
    // the robust way to solve this problem, it’s also quite complex. We’ll do this in
    // Chapter 16, when we implement full stack unwinding.
    // In this section, we rely on using specific compiler options when building 
    // the program to debug, which is `-fno-omit-frame-pointer`. the frame base of the 
    // currently executing function gets stored in the rbp register.
    // The rbp register points to the memory location directly following the return address 
    // for the currently executing function, so to figure out where to set a breakpoint 
    // to step out, we just need to read the memory 8 bytes above the current value of rbp. 
    // If we’re inside of an inlined function, we instead find the end address of the inlined 
    // block. With this knowledge, we can now implement step_out:
    auto tid = otid.value_or(process_->current_thread());
    auto& stack = get_stack(tid);

    std::vector<DIE> inline_stack = stack.inline_stack_at_pc();
    bool has_inline_frames = inline_stack.size() > 1;
    bool at_inline_frame = stack.inline_height() < inline_stack.size() - 1;
    if (has_inline_frames && at_inline_frame) {
        DIE current_frame = inline_stack[inline_stack.size() - stack.inline_height() - 1];
        VirtualAddr return_address = current_frame.high_pc().to_virt_addr();
        return run_until_address(return_address, tid);
    }

    // // Before: 
    // // One place where this algorithm fails to work properly is if the program is halted inside 
    // // a recursive function at least one level deep. In that case, trying to step out may actually 
    // // step into another function call, because the return address can be hit by a recursive call. 
    // // We’ll address this case in Chapter 16, where we’ll implement stack unwinding.
    // auto frame_pointer = process_
    //     ->get_registers()
    //     .read_by_id_as<std::uint64_t>(RegisterId::rbp);

    // auto return_address = process_
    //     ->read_memory_as<std::uint64_t>(VirtualAddr{ frame_pointer + 8 });
    // return run_until_address(VirtualAddr{ return_address });

    // Now:
    // 最终的栈展开规则：
    // 假设 实际函数A中调用实际函数B，实际函数B调用内联C,内联C调用内联D,pc在内联D
    // Stack frames: [实际函数B, 内联C, 内联D, 实际函数A]
    const zdb::Registers& regs = stack.frames()[stack.current_frame_index() + 1].regs;
    VirtualAddr return_address{ regs.read_by_id_as<std::uint64_t>(RegisterId::rip) };
    zdb::StopReason reason;
    for (std::size_t frames = stack.frames().size(); stack.frames().size() >= frames;) {
        reason = run_until_address(return_address, tid);
        if (!reason.is_breakpoint() || process_->get_pc(tid) != return_address) {
            return reason;
        }
    }
    return reason;
}

// find_functions_result find_functions(std::string name) const;
zdb::Target::find_functions_result zdb::Target::find_functions(std::string name) const {
    find_functions_result result;
    elves_.for_each([&](zdb::ELF& elf) {
        std::vector<DIE> dwarf_found = elf.get_dwarf().find_functions(name);
        if (dwarf_found.empty()) {
            std::vector<const Elf64_Sym*> elf_found = elf.get_symbols_by_name(name);
            for (const Elf64_Sym* sym : elf_found) {
                result.elf_functions.push_back(std::pair{ &elf, sym });
            }
        }
        else {
            result.dwarf_functions.insert(
                result.dwarf_functions.end(),
                dwarf_found.begin(), 
                dwarf_found.end()
            );
        }
    });
    
    return result;
}

namespace zdb {
    Breakpoint& Target::create_address_breakpoint(
        VirtualAddr address,
        bool internal,
        bool hardware
    ) {
        return breakpoints_.push(
            std::unique_ptr<AddressBreakpoint>(
                new AddressBreakpoint(*this, address, internal, hardware)
            )
        );
    }

    Breakpoint& Target::create_function_breakpoint(
        std::string function_name,
        bool internal,
        bool hardware
    ) {
        return breakpoints_.push(
            std::unique_ptr<FunctionBreakpoint>(
                new FunctionBreakpoint(*this, function_name, internal, hardware)
            )
        );
    }

    Breakpoint& Target::create_line_breakpoint(
        std::filesystem::path file, 
        std::size_t line,
        bool internal,
        bool hardware
    ) {
        return breakpoints_.push(
            std::unique_ptr<LineBreakpoint>(
                new LineBreakpoint(*this, file, line, internal, hardware)
            )
        );
    }

    std::string Target::function_name_at_address(VirtualAddr address) const {
        FileAddr file_address = address.to_file_addr(elves_);
        const ELF* obj = file_address.elf();
        if (!obj) return "";

        std::optional<DIE> func = obj->get_dwarf().function_containing_address(file_address);
        std::string elf_filename = obj->path().filename().string();
        std::string func_name = "";

        if (func && func->name()) {
            // return std::string{func->name().value()};
            func_name = func->name().value();
        }
        else if (
            std::optional<const Elf64_Sym*> elf_func = obj->get_symbol_at_file_addr(file_address);
            elf_func && ELF64_ST_TYPE(elf_func.value()->st_info) == STT_FUNC
        ) {

            func_name = obj->get_general_str_from_strtab(elf_func.value()->st_name);
            // return abi::__cxa_demangle(
            //     elf_name.c_str(),
            //     nullptr,
            //     nullptr,
            //     nullptr
            // );
        }
        if (!func_name.empty()) 
            return elf_filename + "`" + func_name;

        return "";
    }

    void Target::resolve_dynamic_linker_rendezvous() {
        if (dynamic_linker_rendezvous_address_.addr()) return;

        std::optional<const Elf64_Shdr *>  dynamic_section = main_elf_->get_section_shdr_by_name(".dynamic");
        FileAddr dynamic_start = FileAddr{*main_elf_, dynamic_section.value()->sh_addr};
        std::size_t dynamic_size = dynamic_section.value()->sh_size;
        std::vector<std::byte> dynamic_bytes = 
            process_->read_memory(dynamic_start.to_virt_addr(), dynamic_size);
        
        std::vector<Elf64_Dyn> dynamic_entries(dynamic_size / sizeof(Elf64_Dyn));
        std::copy(
            dynamic_bytes.begin(), 
            dynamic_bytes.end(),
            reinterpret_cast<std::byte*>(dynamic_entries.data())
        );

        for (auto entry : dynamic_entries) {
            if (entry.d_tag == DT_DEBUG) {
                dynamic_linker_rendezvous_address_ = zdb::VirtualAddr{ entry.d_un.d_ptr };
                reload_dynamic_libraries();
                std::optional<r_debug> debug_info = read_dynamic_linker_rendezvous();
                VirtualAddr debug_state_addr = zdb::VirtualAddr{ debug_info->r_brk };
                Breakpoint& debug_state_bp = create_address_breakpoint(
                    debug_state_addr, 
                    true,
                    false
                );
                debug_state_bp.install_hit_handler(
                    [&] {
                        reload_dynamic_libraries();
                        return true;
                    }
                );
                debug_state_bp.enable();
            }
        }

    }

    std::optional<r_debug> Target::read_dynamic_linker_rendezvous() const {
        if (dynamic_linker_rendezvous_address_.addr()) {
            return process_->read_memory_as<r_debug>(dynamic_linker_rendezvous_address_);
        }
        return std::nullopt;
    }

    void Target::reload_dynamic_libraries() {
        std::optional<r_debug> debug = read_dynamic_linker_rendezvous();
        if (!debug) return;

        link_map* entry_ptr = debug->r_map;
        while (entry_ptr != nullptr) {
            VirtualAddr entry_addr = VirtualAddr(reinterpret_cast<std::uint64_t>(entry_ptr));
            link_map entry = process_->read_memory_as<link_map>(entry_addr);
            entry_ptr = entry.l_next;

            VirtualAddr name_addr = VirtualAddr(reinterpret_cast<std::uint64_t>(entry.l_name));
            std::vector<std::byte> name_bytes = process_->read_memory(name_addr, 4096);
            std::filesystem::path name = 
                std::filesystem::path{ reinterpret_cast<char*>(name_bytes.data()) };
            if (name.empty()) continue;

            const ELF* found = nullptr;
            const auto vdso_name = "linux-vdso.so.1";
            if (name == vdso_name) {
                found = elves_.get_elf_by_filename(name.c_str());
            }
            else {
                found = elves_.get_elf_by_path(name);
            }

            if (!found) {
                if (name == vdso_name) {
                    name = dump_vdso(*process_, VirtualAddr{ entry.l_addr });
                }
                auto new_elf = std::make_unique<ELF>(name);
                new_elf->notify_loaded(VirtualAddr{ entry.l_addr });
                elves_.push(std::move(new_elf));
            }
        }
        breakpoints_.for_each([&](auto& bp) {
            bp->resolve();
        });
    }
}; // namespace zdb;

        
