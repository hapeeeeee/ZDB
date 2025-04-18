#include <libzdb/stack.hpp>
#include <libzdb/target.hpp>

namespace zdb {
    void Stack::reset_inline_height() {
        inline_height_ = 0;
        auto stack = inline_stack_at_pc();
        auto pc = target_->get_pc_file_address();
        for (
            auto it = stack.rbegin();
            it != stack.rend() && it->low_pc() == pc;
            ++it
        ) {
            ++inline_height_;
        }
    }

    std::vector<DIE> Stack::inline_stack_at_pc() const {
        auto pc = target_->get_pc_file_address();
        if (!pc.elf()) return {};
        return pc.elf()->get_dwarf().inline_stack_at_file_address(pc);
    }
}