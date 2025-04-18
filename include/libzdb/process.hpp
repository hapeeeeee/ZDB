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
#include <libzdb/watchpoint.hpp>

namespace zdb {
    enum class ProcessState {
        Running,
        Stopped,
        Exited,
        Terminated,
    };

    enum class TrapType {
      Unknown,
      SignalStep,
      Syscall,
      SoftwareBreakpoint,
      HardwareBreakpoint,
    };


   
    struct SyscallInfo {
      // If we request a `PTRACE_SYSCALL` in `prace(PTRACE_SYSCALL, ..)`, 
      // the inferior will halt twice for each syscall: once on entry and once on exit. 
      // This enables the tracer to check the arguments to the syscall before it’s executed 
      // and then check the return value on exit.
      std::uint16_t syscall_id;
      bool is_in_syscall;
      union {
        std::array<std::uint64_t, 6> args;
        std::uint64_t retval;
      };
    };

    struct StopReason {
        StopReason(int wait_status);
        StopReason(
            ProcessState reason, 
            std::uint8_t info, 
            std::optional<TrapType> trap_type = std::nullopt,
            std::optional<SyscallInfo> syscall_info = std::nullopt
        ): reason(reason), info(info), trap_type(trap_type), syscall_info(syscall_info) {}

        bool is_step() const {
            return reason == ProcessState::Stopped
                && info == SIGTRAP
                && trap_type == TrapType::SignalStep;
        }

        bool is_breakpoint() const {
            return reason == ProcessState::Stopped
                && info == SIGTRAP
                && (trap_type == TrapType::SoftwareBreakpoint
                    || trap_type == TrapType::HardwareBreakpoint);
        }

        ProcessState reason;
        std::uint8_t info;
        std::optional<TrapType> trap_type;
        std::optional<SyscallInfo> syscall_info; // only valid if trap_type is TrapType::Syscall
    };

    class SyscallCatchPolicy {
      public:
        enum CatchMode {None, Some, All};

        static SyscallCatchPolicy catch_none() {
          return SyscallCatchPolicy(CatchMode::None, {});
        }

        static SyscallCatchPolicy catch_some(std::vector<int> to_catch) {
          return SyscallCatchPolicy(CatchMode::Some, std::move(to_catch));
        }

        static SyscallCatchPolicy catch_all() {
          return SyscallCatchPolicy(CatchMode::All, {});
        }

        CatchMode get_mode() const { return mode_; }
        const std::vector<int>& get_to_catch() const { return to_catch_; }

      private:
        SyscallCatchPolicy(CatchMode mode, std::vector<int> to_catch)
        : mode_(mode), to_catch_(std::move(to_catch)) {}

        CatchMode mode_ = CatchMode::None;
        std::vector<int> to_catch_;

    };

    class Target;
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
        std::unordered_map<int, std::uint64_t> get_auxv() const;
        void resume();
        StopReason resume_from_untrack_syscall(const StopReason &reason);
        StopReason step();
        StopReason wait_on_signal();
        void augment_trap_type(StopReason &reason);

        void write_user_area(std::size_t offset, std::uint64_t data);
        void write_fprs(const user_fpregs_struct& fprs);
        void write_gprs(const user_regs_struct& gprs);

        Registers& get_registers() { return *registers_; }
        const Registers& get_registers() const { return *registers_; }
        VirtualAddr get_pc() const { return VirtualAddr(get_registers().read_by_id_as<std::uint64_t>(RegisterId::rip)); }
        void set_pc(VirtualAddr addr) { get_registers().write_by_id(RegisterId::rip, addr.addr());}
        void set_target(Target* target) { target_ = target; }  

        pid_t pid() const { return pid_;}
        ProcessState state() const { return state_;}

        BreakpointSite& create_breakpoint_site(VirtualAddr address, bool is_internal = false, bool is_hardware = false);
        StoppointCollection<BreakpointSite>& breakpoint_sites() { return breakpoint_sites_; }
        const StoppointCollection<BreakpointSite>& breakpoint_sites() const { return breakpoint_sites_; }
        int set_hardware_breakpoint(BreakpointSite::id_type id, VirtualAddr address);
        int set_hardware_breakpoint(VirtualAddr address, StopPointMode mode, std::size_t size);

        Watchpoint& create_watchpoint(VirtualAddr addr, StopPointMode mode, std::size_t size);
        StoppointCollection<Watchpoint>& watchpoints() { return watchpoints_; }
        const StoppointCollection<Watchpoint>& watchpoints() const { return watchpoints_; }
        int set_watchpoint(Watchpoint::id_type id, VirtualAddr address, StopPointMode mode, std::size_t size);

        std::variant<BreakpointSite::id_type, Watchpoint::id_type> get_lastest_hardward_stoppoint_id() const;
        void clear_hardware_stoppoint(int id);

        template<class T>
        T read_memory_as(VirtualAddr addr) {
          std::vector<std::byte> data = read_memory(addr, sizeof(T));  
          return from_bytes_as<T>(data.data());
        }
        std::vector<std::byte> read_memory(VirtualAddr addr, std::size_t amount) const;
        std::vector<std::byte> read_memory_without_trap(VirtualAddr addr, std::size_t amount) const;
        void write_memory(VirtualAddr address, Span<const std::byte> data);

        void set_syscall_catch_policy(SyscallCatchPolicy policy) { syscall_catch_policy_ = std::move(policy); }

      private:
        pid_t pid_             = 0;
        bool terminate_on_end_ = true;
        bool is_attached_      = true;
        bool expecting_syscall_exit_ = false;
        ProcessState state_    = ProcessState::Stopped;
        std::unique_ptr<Registers> registers_;
        StoppointCollection<BreakpointSite> breakpoint_sites_;
        StoppointCollection<Watchpoint> watchpoints_;
        SyscallCatchPolicy syscall_catch_policy_ = SyscallCatchPolicy::catch_none();

        Target* target_ = nullptr;
      private:
        Process(pid_t pid, bool terminate_on_end, bool is_attached)
            : pid_(pid), terminate_on_end_(terminate_on_end), is_attached_(is_attached),
              registers_(new Registers(*this)) {}
        
        void read_all_registers();
    };
} // namespace zdb

#endif // LIBZDB_PROCESS_HPP
