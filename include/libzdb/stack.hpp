#ifndef LIBZDB_STACK_HPP
#define LIBZDB_STACK_HPP
#include <vector>
#include <libzdb/dwarf.hpp>
#include <libzdb/registers.hpp>
#include <libzdb/types.hpp>

namespace zdb {
    class Target;

    struct StackFrame {
      Registers regs;
      VirtualAddr backtrace_report_address;
      DIE func_die;
      bool inlined = false;
      SourceLocation location;
    };

    class Stack {
      public:
        Stack(Target* tgt) : target_(tgt) {}
        void reset_inline_height();
        std::vector<zdb::DIE> inline_stack_at_pc() const;
        std::uint32_t inline_height() const { return inline_height_; }
        const Target& get_target() const { return *target_; }

        void simulate_inlined_step_in() { 
          --inline_height_;
          current_frame_ = inline_height_;
        }

        void unwind();
        void up() { ++current_frame_; }
        void down() { --current_frame_; }

        // This function will return the current set of frames, not including
        // those that the compiler inlined (which we’re pretending the process 
        // hasn’t yet entered).
        Span<const StackFrame> frames() const;
        bool has_frames() const { return !frames_.empty(); }
        const StackFrame& current_frame() const { return frames_[current_frame_]; }


        std::size_t current_frame_index() const {
          return current_frame_ - inline_height_;
        }
        const Registers& regs() const;
        VirtualAddr get_pc() const;
      
      private:
        void create_inline_stack_frames(
            const Registers& regs,
            const std::vector<DIE> inline_stack,
            FileAddr pc
        );

        void create_base_frame(
            const Registers& regs,
            const std::vector<DIE> inline_stack,
            FileAddr pc,
            bool inlined
        );

      private:
        Target* target_ = nullptr;
        std::uint32_t inline_height_ = 0;

        std::vector<StackFrame> frames_;
        std::size_t current_frame_ = 0;
    };
}

#endif