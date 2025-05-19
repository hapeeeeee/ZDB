#include <libzdb/stack.hpp>
#include <libzdb/target.hpp>

namespace zdb {
    void Stack::reset_inline_height() {
        inline_height_ = 0;
        std::vector<DIE> stack = inline_stack_at_pc();
        FileAddr pc = target_->get_pc_file_address();
        for (
            auto it = stack.rbegin();
            it != stack.rend() && it->low_pc() == pc;
            ++it
        ) {
            ++inline_height_;
        }
    }

    std::vector<DIE> Stack::inline_stack_at_pc() const {
        FileAddr pc = target_->get_pc_file_address();
        if (!pc.elf()) return {};
        return pc.elf()->get_dwarf().inline_stack_at_file_address(pc);
    }

    Span<const StackFrame> Stack::frames() const {
        return { frames_.data() + inline_height_, frames_.size() - inline_height_ };
    }

    const Registers& Stack::regs() const {
        return frames_[current_frame_].regs;
    }

    VirtualAddr Stack::get_pc() const {
        return VirtualAddr{
            regs().read_by_id_as<std::uint64_t>(RegisterId::rip)
        };
    }

    void Stack::unwind() {
        reset_inline_height();
        current_frame_ = inline_height_;

        VirtualAddr virl_addr_pc = target_->get_process().get_pc();
        FileAddr file_addr_pc =  target_->get_pc_file_address();
        Process& proc = target_->get_process();
        Registers regs = proc.get_registers();

        frames_.clear();

        // Ensure that the program counter points to a valid ELF file and
        // then keep unwinding frames until we hit a frame with a program counter
        // that lives outside of the ELF file we’re operating on (indicating that this
        // function belongs to some shared library or that we’ve hit the topmost frame)
        const ELF * elf = file_addr_pc.elf();
        if (!elf) return;
        while (virl_addr_pc.addr() != 0 && elf == &target_->get_elf()) {
            // Create stack_frame objects and unwind another frame.
            const Dwarf &dwarf = elf->get_dwarf();
            std::vector<zdb::DIE> inline_stacks = dwarf.inline_stack_at_file_address(file_addr_pc);
            if (inline_stacks.empty()) return;

            if (inline_stacks.size() > 1) {
                create_base_frame(regs, inline_stacks, file_addr_pc, true);
                create_inline_stack_frames(regs, inline_stacks, file_addr_pc);
            } else {
                create_base_frame(regs, inline_stacks, file_addr_pc, false);
            }
            
            regs = dwarf.cfi().unwind(proc, file_addr_pc, frames_.back().regs);
            virl_addr_pc = VirtualAddr{
                regs.read_by_id_as<std::uint64_t>(RegisterId::rip) - 1
            };
            file_addr_pc = virl_addr_pc.to_file_addr(target_->get_elf());
        }
    }

    void Stack::create_inline_stack_frames(
        const Registers& regs,
        const std::vector<DIE> inline_stack,
        FileAddr pc
    ) {
        for (auto it = inline_stack.rbegin() + 1; it != inline_stack.rend(); ++it) {
            auto inlined_pc = std::prev(it)->low_pc().to_virt_addr();
            frames_.push_back(StackFrame{ regs, inlined_pc, *it });
            frames_.back().inlined = std::next(it) != inline_stack.rend();
            frames_.back().location = std::prev(it)->location();
        }
    }

    void Stack::create_base_frame(
        const Registers& regs,
        const std::vector<DIE> inline_stacks,
        FileAddr file_pc,
        bool inlined
    ) {
        VirtualAddr backtrace_pc = file_pc.to_virt_addr();
        LineTable::iterator line_entry = file_pc.elf()->get_dwarf().line_entry_at_address(file_pc);
        if (line_entry != LineTable::iterator{}) {
            backtrace_pc = line_entry->address.to_virt_addr();
        }
            
        frames_.push_back({ regs, backtrace_pc, inline_stacks.back(), inlined });
        frames_.back().location = SourceLocation{ line_entry->file_entry, line_entry->line };
    }

}
