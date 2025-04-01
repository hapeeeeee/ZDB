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
    
      private:
        Target(std::unique_ptr<Process> process, std::unique_ptr<ELF> elf)
        : process_(std::move(process)), elf_(std::move(elf)) {}
      private:
        std::unique_ptr<Process> process_;
        std::unique_ptr<ELF> elf_;
    };
}

#endif // LIBZDB_TARGET_HPP