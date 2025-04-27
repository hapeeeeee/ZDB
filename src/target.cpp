#include <libzdb/target.hpp>
#include <libzdb/elf.hpp>
#include <optional>
#include <libzdb/disassembler.hpp>

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
    return target;
}

zdb::FileAddr zdb::Target::get_pc_file_address() const {
    return process_->get_pc().to_file_addr(*elf_);
}

zdb::LineTable::iterator zdb::Target::line_entry_at_pc() const {
    FileAddr pc = get_pc_file_address();
    if (!pc.elf()) return LineTable::iterator();
    const CompileUnit* cu = pc.elf()->get_dwarf().compile_unit_containing_address(pc);
    if (!cu) return LineTable::iterator();
    return cu->lines().get_entry_by_address(pc);
}

zdb::StopReason zdb::Target::run_until_address(VirtualAddr address) {
    BreakpointSite* breakpoint_to_remove = nullptr;
    if (!process_->breakpoint_sites().contains_address(address)) {
        breakpoint_to_remove = &process_->create_breakpoint_site(
            address, 
            true,
            false
        );
        breakpoint_to_remove->enable();
    }
    process_->resume();
    auto reason = process_->wait_on_signal();
    if (reason.is_breakpoint() && process_->get_pc() == address) {
        reason.trap_type = TrapType::SignalStep;
    }
    if (breakpoint_to_remove) {
        process_->breakpoint_sites().remove_by_address(breakpoint_to_remove->address());
    }
    return reason;
}

void zdb::Target::notify_stop(const StopReason& reason) {
    stack_.reset_inline_height();
}

zdb::StopReason zdb::Target::step_in() {
    zdb::Stack& stack = get_stack();
    if (stack.inline_height() > 0) {
        stack.simulate_inlined_step_in();
        return StopReason(ProcessState::Stopped, SIGTRAP, TrapType::SignalStep, std::nullopt);
    }

    auto orig_line = line_entry_at_pc();
    do {
        auto reason = process_->step();
        if (!reason.is_step()) {
            // Stopped at a breakpoint or terminated completely
            return reason;
        }
    } while ((line_entry_at_pc() == orig_line || line_entry_at_pc()->end_sequence)
            && line_entry_at_pc() != LineTable::iterator{});

    // we may still need to step over the function prologue
    // if we’ve entered a new function
    auto pc = get_pc_file_address();
    if (pc.elf() != nullptr) {
        auto& dwarf = pc.elf()->get_dwarf();
        auto func = dwarf.function_containing_address(pc);
        if (func && func->low_pc() == pc) {
            auto line = line_entry_at_pc();
            if (line != LineTable::iterator{}) {
                ++line;
                return run_until_address(line->address.to_virt_addr());
            }
        }
    }

    return StopReason(ProcessState::Stopped, SIGTRAP, TrapType::SignalStep, std::nullopt);
}

zdb::StopReason zdb::Target::step_over() {
    LineTable::iterator orig_line = line_entry_at_pc();
    Disassembler disas(*process_);

    zdb::StopReason reason;
    auto& stack = get_stack();
    do {
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
                reason = run_until_address(return_address);
                if (!reason.is_step() || process_->get_pc() != return_address) {
                    return reason;
                }
            }
            else if (
                auto instructions = disas.disassemble(2, process_->get_pc());
                instructions[0].text.rfind("call") == 0
            ) {
                reason = run_until_address(instructions[1].address);
                if (!reason.is_step() || process_->get_pc() != instructions[1].address) {
                    return reason;
                }
            }
            else {
                reason = process_->step();
                if (!reason.is_step()) return reason;
            }
        
        } while (line_entry_at_pc() == orig_line || line_entry_at_pc()->end_sequence);

    } while ((line_entry_at_pc() == orig_line || line_entry_at_pc()->end_sequence)
        && line_entry_at_pc() != LineTable::iterator{});

    return reason;
}

zdb::StopReason zdb::Target::step_out() {
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
    zdb::Stack& stack = get_stack();
    std::vector<DIE> inline_stack = stack.inline_stack_at_pc();
    bool has_inline_frames = inline_stack.size() > 1;
    bool at_inline_frame = stack.inline_height() < inline_stack.size() - 1;
    if (has_inline_frames && at_inline_frame) {
        DIE current_frame = inline_stack[inline_stack.size() - stack.inline_height() - 1];
        VirtualAddr return_address = current_frame.high_pc().to_virt_addr();
        return run_until_address(return_address);
    }

    // One place where this algorithm fails to work properly is if the program is halted inside 
    // a recursive function at least one level deep. In that case, trying to step out may actually 
    // step into another function call, because the return address can be hit by a recursive call. 
    // We’ll address this case in Chapter 16, where we’ll implement stack unwinding.
    auto frame_pointer = process_
        ->get_registers()
        .read_by_id_as<std::uint64_t>(RegisterId::rbp);

    auto return_address = process_
        ->read_memory_as<std::uint64_t>(VirtualAddr{ frame_pointer + 8 });
    return run_until_address(VirtualAddr{ return_address });
}

// find_functions_result find_functions(std::string name) const;
zdb::Target::find_functions_result zdb::Target::find_functions(std::string name) const {
    find_functions_result result;
    std::vector<DIE> dwarf_found = elf_->get_dwarf().find_functions(name);
    if (dwarf_found.empty()) {
        std::vector<const Elf64_Sym*> elf_found = elf_->get_symbols_by_name(name);
        for (const Elf64_Sym* sym : elf_found) {
            result.elf_functions.push_back(std::pair{ elf_.get(), sym });
        }
    }
    else {
        result.dwarf_functions.insert(
            result.dwarf_functions.end(),
            dwarf_found.begin(), 
            dwarf_found.end()
        );
    }
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

};

        
