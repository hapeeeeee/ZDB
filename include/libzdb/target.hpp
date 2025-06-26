// Implement the zdb::target type, which will manage the symbolic level of the program
// that we’re debugging, such as storing the zdb::elf object for the program, reading debug information, 
// and carrying out debugger operations at the level of the source code. 
// Begin this type in a new zdb/include/libsdb/target.hpp file. 
// It should have a process, an object file, and functions for retrieving these. 
// Like zdb::process, it should be non-copyable and constructible only with launch and attach static members:

#ifndef LIBZDB_TARGET_HPP
#define LIBZDB_TARGET_HPP

#include <memory>
#include <optional>
#include <libzdb/process.hpp>
#include <libzdb/elf.hpp>
#include <libzdb/stack.hpp>
#include <libzdb/breakpoint.hpp>
#include <link.h>


namespace zdb {
    struct Thread {
        Thread(ThreadState* state, Stack frames)
            : state(state), frames(std::move(frames)) {}
        ThreadState *state;
        Stack frames;
    };

    class Target {
      public:
        Target() = delete;
        Target(const Target &) = delete;
        Target &operator=(const Target &) = delete;

        static std::unique_ptr<Target> launch(
            std::filesystem::path path, 
            std::optional<int> stdout_fd = std::nullopt
        );
        static std::unique_ptr<Target> attach(pid_t pid);

        Process& get_process() { return *process_; }
        const Process& get_process() const { return *process_; }
        Stack& get_stack(std::optional<pid_t> otid = std::nullopt) { 
          	auto tid = otid.value_or(process_->current_thread());
            return threads_.at(tid).frames;
        }
        const Stack& get_stack(std::optional<pid_t> otid = std::nullopt) const { 
            return const_cast<Target*>(this)->get_stack(otid);
        }

        ELFCollection& get_elves() { return elves_; }
        const ELFCollection& get_elves() const { return elves_; }
        ELF& get_main_elf() { return *main_elf_; }
        const ELF& get_main_elf() const { return *main_elf_; }

        std::unordered_map<pid_t, Thread>& get_threads() { return threads_; }
        const std::unordered_map<pid_t, Thread>& get_threads() const { return threads_; }
        void notify_thread_lifecycle_event(const zdb::StopReason& reason);

        FileAddr get_pc_file_address(std::optional<pid_t> otid = std::nullopt) const;
        void notify_stop(const StopReason& reason);

        LineTable::iterator line_entry_at_pc(std::optional<pid_t> otid = std::nullopt) const;
        std::vector<LineTable::iterator> get_line_entries_by_line(
          std::filesystem::path path, 
          std::size_t line
        ) const;
        StopReason run_until_address(VirtualAddr address, std::optional<pid_t> otid = std::nullopt);

        StopReason step_in(std::optional<pid_t> otid = std::nullopt);
        StopReason step_out(std::optional<pid_t> otid = std::nullopt);
        StopReason step_over(std::optional<pid_t> otid = std::nullopt);

        // This Struct only for `FunctionBreakpoint`
        struct find_functions_result {
          std::vector<DIE> dwarf_functions;
          // May be used by share lib
          std::vector<std::pair<const ELF*, const Elf64_Sym*>> elf_functions;
        };
        find_functions_result find_functions(std::string name) const;


        Breakpoint& create_address_breakpoint(
            VirtualAddr address,
            bool internal = false,
            bool hardware = false 
        );
        Breakpoint& create_function_breakpoint(
            std::string function_name,
            bool internal = false,
            bool hardware = false 
        );
        Breakpoint& create_line_breakpoint(
            std::filesystem::path file, 
            std::size_t line,
            bool internal = false,
            bool hardware = false 
        );

        StoppointCollection<Breakpoint>& breakpoints() { return breakpoints_; }
        const StoppointCollection<Breakpoint>& breakpoints() const { return breakpoints_; }

        std::string function_name_at_address(VirtualAddr address) const;

        std::optional<r_debug> read_dynamic_linker_rendezvous() const;
        void resolve_dynamic_linker_rendezvous();
        void reload_dynamic_libraries();

        std::vector<std::byte> read_location_data(
            const DwarfExpression::result& loc, 
            std::size_t size,
            std::optional<pid_t> otid = std::nullopt
        ) const;


      private:
        Target(std::unique_ptr<Process> process, std::unique_ptr<ELF> elf)
        : process_(std::move(process)), 
          main_elf_(elf.get())
        {
            elves_.push(std::move(elf));
            pid_t pid = process_->pid();
            for (auto& [tid, state] : process_->thread_states()) {
                threads_.emplace(tid, Thread(&state, Stack{this, tid}));
            }
        }

      private:
        std::unique_ptr<Process> process_;
        ELF* main_elf_;
        ELFCollection elves_;
        // Stack stack_;
        StoppointCollection<Breakpoint> breakpoints_;
        VirtualAddr dynamic_linker_rendezvous_address_;
        std::unordered_map<pid_t, Thread> threads_;
    };
}

#endif // LIBZDB_TARGET_HPP