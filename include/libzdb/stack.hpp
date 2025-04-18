#ifndef LIBZDB_STACK_HPP
#define LIBZDB_STACK_HPP
#include <vector>
#include <libzdb/dwarf.hpp>

namespace zdb {
    class Target;
    class Stack {
      public:
        Stack(Target* tgt) : target_(tgt) {}
        void reset_inline_height();
        std::vector<zdb::DIE> inline_stack_at_pc() const;
        std::uint32_t inline_height() const { return inline_height_; }
        const Target& get_target() const { return *target_; }

        void simulate_inlined_step_in() { --inline_height_; }
      
      private:
        Target* target_ = nullptr;
        std::uint32_t inline_height_ = 0;
    };
}

#endif