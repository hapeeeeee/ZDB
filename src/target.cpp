#include <libzdb/target.hpp>
#include <libzdb/elf.hpp>


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

}

zdb::StopReason zdb::Target::run_until_address(VirtualAddr address) {
    
}

void zdb::Target::notify_stop(const StopReason& reason) {
    stack_.reset_inline_height();
}

zdb::StopReason zdb::Target::step_in() {
    auto& stack = get_stack();
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
            && line_entry_at_pc() != LineTable::iterator{}
    );

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

zdb::StopReason zdb::Target::step_out() {
    
}

zdb::StopReason zdb::Target::step_over() {
    
}