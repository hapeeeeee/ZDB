#ifndef LIBZDB_PROCESS_HPP
#define LIBZDB_PROCESS_HPP

#include <filesystem>
#include <iostream>
#include <memory>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libzdb/registers.hpp>
#include <optional>
#include <libzdb/breakpoint_site.hpp>
#include <libzdb/stoppoint_collection.hpp>
#include <libzdb/bit.hpp>
namespace zdb {
    enum class ProcessState {
        Running,
        Stopped,
        Exited,
        Terminated,
    };

    struct StopReason {
        StopReason(int wait_status);

        ProcessState reason;
        std::uint8_t info;
    };

    class Process {
      public:
        Process()                = delete;
        Process(const Process &) = delete;
        Process &operator=(const Process &) = delete;
        ~Process();

      public:
        static std::unique_ptr<Process> attach(pid_t pid);
        static std::unique_ptr<Process> launch(
          std::filesystem::path path, 
          bool debug = true,
          std::optional<int> stdout_fd = std::nullopt
        );
        void resume();
        StopReason step();
        StopReason wait_on_signal();

        void write_user_area(std::size_t offset, std::uint64_t data);
        void write_fprs(const user_fpregs_struct& fprs);
        void write_gprs(const user_regs_struct& gprs);

        Registers& get_registers() { return *registers_; }
        const Registers& get_registers() const { return *registers_; }
        VirtualAddr get_pc() const { return VirtualAddr(get_registers().read_by_id_as<std::uint64_t>(RegisterId::rip)); }
        void set_pc(VirtualAddr addr) { get_registers().write_by_id(RegisterId::rip, addr.addr());}

        pid_t pid() const { return pid_;}
        ProcessState state() const { return state_;}

        BreakpointSite& create_breakpoint_site(VirtualAddr address);
        StoppointCollection<BreakpointSite>& breakpoint_sites() { return breakpoint_sites_; }
        const StoppointCollection<BreakpointSite>& breakpoint_sites() const { return breakpoint_sites_; }

        template<class T>
        T read_memory_as(VirtualAddr addr) {
          std::vector<std::byte> data = read_memory(addr, sizeof(T));  
          return from_bytes_as<T>(data.data());
        }
        std::vector<std::byte> read_memory(VirtualAddr addr, std::size_t amount);
        void write_memory(VirtualAddr address, Span<const std::byte> data);


      private:
        pid_t pid_             = 0;
        bool terminate_on_end_ = true;
        bool is_attached_      = true;
        ProcessState state_    = ProcessState::Stopped;
        std::unique_ptr<Registers> registers_;
        StoppointCollection<BreakpointSite> breakpoint_sites_;

      private:
        Process(pid_t pid, bool terminate_on_end, bool is_attached)
            : pid_(pid), terminate_on_end_(terminate_on_end), is_attached_(is_attached),
              registers_(new Registers(*this)) {}
        
        void read_all_registers();
        
    };
} // namespace zdb

#endif // LIBZDB_PROCESS_HPP
