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


namespace zdb {
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
        ELF& get_elf() { return *elf_; }
        const ELF& get_elf() const { return *elf_; }
        Stack& get_stack() { return stack_; }
        const Stack& get_stack() const { return stack_; }

        FileAddr get_pc_file_address() const;
        void notify_stop(const StopReason& reason);

        LineTable::iterator line_entry_at_pc() const;
        StopReason run_until_address(VirtualAddr address);

        StopReason step_in();
        StopReason step_out();
        StopReason step_over();

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

      private:
        Target(std::unique_ptr<Process> process, std::unique_ptr<ELF> elf)
        : process_(std::move(process)), elf_(std::move(elf)), stack_(this) {}

      private:
        std::unique_ptr<Process> process_;
        std::unique_ptr<ELF> elf_;
        Stack stack_;
        StoppointCollection<Breakpoint> breakpoints_;

    };
}

#endif // LIBZDB_TARGET_HPP