#include <libzdb/error.hpp>
#include <libzdb/pipe.hpp>
#include <libzdb/process.hpp>
#include <sys/personality.h>
#include <sys/uio.h>
#include <libzdb/bit.hpp>
#include <fstream>
#include <elf.h>
#include <libzdb/target.hpp>
namespace {
    void set_ptrace_options(pid_t pid) {
        if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD) < 0) {
            zdb::Error::send_errno("Set ptrace options failed");
        }
    }

    void exit_with_perror(zdb::Pipe &pipe, const std::string &prefix) {
        std::string msg = prefix + ": " + std::strerror(errno);
        pipe.write(reinterpret_cast<std::byte *>(msg.data()), msg.size());
        exit(-1);
    }

    int find_free_stoppoint_register(std::uint64_t data_of_controler_dr7) {
        for (int i = 0; i < 4; ++i) {
            if ((data_of_controler_dr7 & (0b11 << (i * 2))) == 0) {
                return i;
            }
        }
        zdb::Error::send("No remaining hardware debug registers");
    }

    std::uint64_t encode_hardware_breakpoint_mode(zdb::StopPointMode mode) {
        switch (mode) {
            case zdb::StopPointMode::Execute:
                return 0b00;
            case zdb::StopPointMode::Write:
                return 0b01;
            case zdb::StopPointMode::ReadWrite:
                return 0b11;
            default:
                zdb::Error::send("Invalid stop point mode");
        }
    }

    std::uint64_t encode_hardware_breakpoint_size(std::size_t size) {
        switch (size) {
            case 1:
                return 0b00;
            case 2:
                return 0b01;
            case 4:
                return 0b11;
            case 8:
                return 0b10;
            default:
                zdb::Error::send("Invalid hardware breakpoint size");
        }
    }
} // namespace

zdb::StopReason::StopReason(int wait_status) {
    if (WIFSTOPPED(wait_status)) {
        reason = ProcessState::Stopped;
        info   = WSTOPSIG(wait_status);
    } else if (WIFEXITED(wait_status)) {
        reason = ProcessState::Exited;
        info   = WEXITSTATUS(wait_status);
    } else if (WIFSIGNALED(wait_status)) {
        reason = ProcessState::Terminated;
        info   = WTERMSIG(wait_status);
    }
}

zdb::Process::~Process() {
    if (pid_ == 0) {
        return;
    }
    int status;
    if (is_attached_) {
        if (state_ == ProcessState::Running) {
            kill(pid_, SIGSTOP);
            waitpid(pid_, &status, 0);
        }
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        kill(pid_, SIGCONT);
    }

    if (terminate_on_end_) {
        kill(pid_, SIGKILL);
        waitpid(pid_, &status, 0);
    }
}

std::unique_ptr<zdb::Process> zdb::Process::attach(pid_t pid) {
    if (pid <= 0) {
        Error::send("Invalid PID");
    }
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        Error::send_errno("Attach failed");
    }

    std::unique_ptr<Process> proc(new Process(pid, /*terminate_on_end=*/false, /*is_attached=*/true));
    proc->wait_on_signal();
    set_ptrace_options(pid);
    return proc;
}

std::unique_ptr<zdb::Process> zdb::Process::launch(
    std::filesystem::path path, 
    bool debug, 
    std::optional<int> stdout_fd
) {
    zdb::Pipe channel(/*close_on_exec=*/true);
    pid_t pid = fork();
    if (pid < 0) {
        Error::send_errno("Fork failed");
    } else if (pid == 0) {
        // Now in child process, execute the debuggee
        if (setpgid(0, 0) < 0) {
            exit_with_perror(channel, "Setpgid failed");
        }
        personality(ADDR_NO_RANDOMIZE);
        channel.close_read();
        if (stdout_fd) {
            if (dup2(*stdout_fd, STDOUT_FILENO) < 0) {
                exit_with_perror(channel, "Dup2 failed");
            }
        }
        if (debug && ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
            exit_with_perror(channel, "Trace failed");
        }
        if (execlp(path.c_str(), path.c_str(), nullptr) < 0) {
            exit_with_perror(channel, "Exec failed");
        }
    }

    // Since Pipe's `close_on_exec` is set to true, if `execlp` succeeds,
    // the child process will close the write end of the pipe.
    // As a result, the read operation in the parent process will unblock
    // because the other end of the pipe is completely closed.
    // If `execlp` fails, the child process remains alive, and the pipe
    // stays open, allowing the child process to write data to the pipe
    // for the parent process to read.
    channel.close_write();
    std::vector<std::byte> msg = channel.read();
    channel.close_read();

    if (msg.size() > 0) {
        waitpid(pid, nullptr, 0);
        auto chars = reinterpret_cast<char *>(msg.data());
        zdb::Error::send(std::string(chars, chars + msg.size()));
    }

    std::unique_ptr<Process> proc(new Process(pid, /*terminate_on_end=*/true, /*is_attached=*/debug));
    if (debug) {
        // Since the child process set ptrace with `PTRACE_TRACEME` before calling `execlp`,
        // this causes the newly executed process to stop immediately after `execlp`.
        // This state change triggers a signal in the child process,
        // allowing `waitpid` to return without blocking.
        proc->wait_on_signal();
        set_ptrace_options(pid);
    }
    return proc;
}

std::unordered_map<int, std::uint64_t> zdb::Process::get_auxv() const {
    auto path = "/proc/" + std::to_string(pid_) + "/auxv";
    std::ifstream auxv_file(path);

    std::unordered_map<int, std::uint64_t> auxv;
    std::uint64_t id_key, value;
    auto read_auxv = [&](auto &into) {
        auxv_file.read(reinterpret_cast<char *>(&into), sizeof(into));
    };

    for (read_auxv(id_key); id_key != AT_NULL; read_auxv(id_key)) {
        read_auxv(value);
        auxv[id_key] = value;
    }
    return auxv;
}

void zdb::Process::resume() {
    auto pc = get_pc();
    if (breakpoint_sites_.enabled_stoppoint_at_address(pc)) {
        auto &bp = breakpoint_sites_.get_by_address(pc);
        bp.disable();
        if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) < 0) {
            Error::send_errno("Single Step after breakpoint failed");
        }

        int status;
        if (waitpid(pid_, &status, 0) < 0) {
            Error::send_errno("Wait after single step failed");
        }
        bp.enable();
    } 

    auto ptrace_req = 
        syscall_catch_policy_.get_mode() == SyscallCatchPolicy::CatchMode::None ?
            PTRACE_CONT : 
            PTRACE_SYSCALL;
    if (ptrace(ptrace_req, pid_, nullptr, nullptr) < 0) {
        Error::send_errno("Continue failed");
    }
    state_ = ProcessState::Running;
}

zdb::StopReason zdb::Process::resume_from_untrack_syscall(const StopReason &reason) {
    if (syscall_catch_policy_.get_mode() == SyscallCatchPolicy::CatchMode::Some) {
        const std::vector<int> &to_catch = syscall_catch_policy_.get_to_catch();
        auto found = std::find(to_catch.begin(), to_catch.end(), reason.syscall_info->syscall_id);
        if (found == end(to_catch)) {
            resume();
            return wait_on_signal();
        }
    }

    return reason;
}

zdb::StopReason zdb::Process::step() {
    std::optional<BreakpointSite*> to_reenable;
    VirtualAddr pc = get_pc();
    if (breakpoint_sites_.enabled_stoppoint_at_address(pc)) {
        BreakpointSite &bp = breakpoint_sites_.get_by_address(pc);
        bp.disable();
        to_reenable = &bp;
    }

    if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) < 0) {
        Error::send_errno("Single Step failed");
    }
    
    StopReason stop_reason = wait_on_signal();
    if (to_reenable) {
        to_reenable.value()->enable();
    }
    return stop_reason;
}

zdb::StopReason zdb::Process::wait_on_signal() {
    int wait_status;
    if (waitpid(pid_, &wait_status, 0) < 0) {
        Error::send_errno("Wait signal failed");
    }

    StopReason stop_reason(wait_status);
    state_ = stop_reason.reason;
    if (!is_attached_ || state_ != ProcessState::Stopped) {
        return stop_reason;
    }

    read_all_registers();
    augment_trap_type(stop_reason);
    if (stop_reason.info != SIGTRAP) {
        return stop_reason;
    }

    auto instr_begin = get_pc() - 1;
    if (stop_reason.trap_type == TrapType::SoftwareBreakpoint 
        && breakpoint_sites_.enabled_stoppoint_at_address(instr_begin)
    ) {
        set_pc(instr_begin);

        auto& bp = breakpoint_sites_.get_by_address(instr_begin);
        if (bp.parent_) {
            bool should_restart = bp.parent_->notify_hit();
            if (should_restart) {
                resume();
                return wait_on_signal();
            }
        }
    } 
    else if (stop_reason.trap_type == TrapType::HardwareBreakpoint) {
        auto id = get_lastest_hardward_stoppoint_id();
        if (id.index() == 1) {
            watchpoints_.get_by_id(std::get<1>(id)).update_data();
        }
    }
    else if (stop_reason.trap_type == TrapType::Syscall) {
        stop_reason = resume_from_untrack_syscall(stop_reason);
    }

    if (target_) {
        target_->notify_stop(stop_reason);
    } 
    
    return stop_reason;
}

void zdb::Process::augment_trap_type(StopReason &reason) {
    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO, pid_, nullptr, &info) < 0) {
        Error::send_errno("Get signal info failed");
    }

    // Now that we’ve enabled `PTRACE_O_TRACESYSGOOD` option, 
    // the signal number will have its eighth bit set if the SIGTRAP came from a syscall. 
    // This means we can use signal ==  to check whether we’re trapped by a syscall. 
    if (reason.info == (SIGTRAP | 0x80)) {
        auto &syscall_info = reason.syscall_info.emplace();
        auto &regs = get_registers();

        if (expecting_syscall_exit_) {
            syscall_info.is_in_syscall = false;
            expecting_syscall_exit_ = false;

            syscall_info.syscall_id = regs.read_by_id_as<std::uint64_t>(RegisterId::orig_rax);
            syscall_info.retval = regs.read_by_id_as<std::uint64_t>(RegisterId::rax);
        } else {
            syscall_info.is_in_syscall = true;
            expecting_syscall_exit_ = true;

            syscall_info.syscall_id = regs.read_by_id_as<std::uint64_t>(RegisterId::orig_rax);
            std::array<RegisterId, 6> arg_regs = {
                RegisterId::rdi, 
                RegisterId::rsi, 
                RegisterId::rdx,
                RegisterId::r10, 
                RegisterId::r8, 
                RegisterId::r9
            };
            for (auto i = 0; i < 6; ++i) {
                syscall_info.args[i] = regs.read_by_id_as<std::uint64_t>(arg_regs[i]);
            }
        }

        reason.trap_type = TrapType::Syscall;
        reason.info = SIGTRAP;
        return;
    }

    expecting_syscall_exit_ = false;
    reason.trap_type = TrapType::Unknown;
    if (info.si_signo == SIGTRAP) {
        switch (info.si_code) {
            case TRAP_TRACE:
                reason.trap_type = TrapType::SignalStep;
                break;
            case SI_KERNEL:
                reason.trap_type = TrapType::SoftwareBreakpoint;
                break;
            case TRAP_HWBKPT:
                reason.trap_type = TrapType::HardwareBreakpoint;
                break;
            default:
                break;
        }
    }
}

void zdb::Process::read_all_registers() {
    if (ptrace(PTRACE_GETREGS, pid_, nullptr, &get_registers().data_.regs) < 0) {
        Error::send_errno("Read registers failed");
    }
    if (ptrace(PTRACE_GETFPREGS, pid_, nullptr, &get_registers().data_.i387) < 0) {
        Error::send_errno("Read FPU registers failed");
    }

    for (int i = 0; i < 8; ++i) {
        auto id = static_cast<int>(RegisterId::dr0) + i;
        auto info = find_register_info_by_id(static_cast<RegisterId>(id));
        errno = 0;
        std::int64_t data = ptrace(PTRACE_PEEKUSER, pid_, info.offset, nullptr); 
        if (errno != 0) {
            zdb::Error::send_errno("Could not read debug register");
        }
        get_registers().data_.u_debugreg[i] = data;
    }
}

void zdb::Process::write_user_area(std::size_t offset, std::uint64_t data) {
    if (ptrace(PTRACE_POKEUSER, pid_, offset, data) < 0) {
        Error::send_errno("Write user area failed");
    }
}

void zdb::Process::write_fprs(const user_fpregs_struct& fprs) {
    if (ptrace(PTRACE_SETFPREGS, pid_, nullptr, &fprs) < 0) {
        Error::send_errno("Could not write floating point registers");
    }
}

void zdb::Process::write_gprs(const user_regs_struct& gprs) {
    if (ptrace(PTRACE_SETREGS, pid_, nullptr, &gprs) < 0) {
        Error::send_errno("Could not write general purpose registers");
    }
}

zdb::BreakpointSite& zdb::Process::create_breakpoint_site(
    VirtualAddr address, 
    bool is_internal, 
    bool is_hardware
) {
    if (breakpoint_sites_.contains_address(address)) {
        Error::send(
            "Breakpoint site already exists as address " + std::to_string(address.addr())
        );
    }
    auto site = std::unique_ptr<BreakpointSite>(
        new BreakpointSite(*this, address, is_internal, is_hardware)
    );
    return breakpoint_sites_.push(std::move(site));
}

zdb::BreakpointSite& zdb::Process::create_breakpoint_site(
    Breakpoint* parent, 
    BreakpointSite::id_type id, 
    VirtualAddr address,
    bool hardware, 
    bool internal
) {
    if (breakpoint_sites_.contains_address(address)) {
        Error::send(
            "Breakpoint site already exists as address " + std::to_string(address.addr())
        );
    }

    return breakpoint_sites_.push(
        std::unique_ptr<BreakpointSite>(
            new BreakpointSite(*this, parent, id, address, hardware, internal)
        )
    );
}

std::vector<std::byte> zdb::Process::read_memory(VirtualAddr addr, std::size_t amount) const {
    std::vector<std::byte> result(amount);
    iovec local_iov = {result.data(), result.size()};
    std::vector<iovec> remote_iov;

    /// why page-by-page read???
    while (amount > 0) {
        auto remaining_in_current_mem_page = 0x1000 - (addr.addr() & 0xfff);
        auto to_read = std::min(remaining_in_current_mem_page, amount);
        remote_iov.push_back({reinterpret_cast<void*>(addr.addr()), to_read});
        amount -= to_read;
        addr += to_read;
    }

    if (process_vm_readv(
        pid_, 
        &local_iov, 1, 
        remote_iov.data(), remote_iov.size(), 
        0
    ) < 0) {
        Error::send_errno("Read memory failed");
    }
    return result;
}

std::vector<std::byte> zdb::Process::read_memory_without_trap(VirtualAddr addr, std::size_t amount) const { 
    auto mem_data = read_memory(addr, amount);
    std::vector<BreakpointSite*> sites = breakpoint_sites_.get_in_region(addr, addr + amount);
    for (auto site : sites) {
        if (!site->is_enabled() || site->is_hardware()) {
            continue;
        }
        auto offset = site->address() - addr.addr();
        mem_data[offset.addr()] = site->saved_data();   
    }
    return mem_data;
}

void zdb::Process::write_memory(VirtualAddr address, Span<const std::byte> data) {
    std::size_t written = 0;
    while (written < data.size()) {
        std::uint64_t qword;
        auto remaining_data_size = data.size() - written;
        if (remaining_data_size >= 8) {
            qword = from_bytes_as<std::uint64_t>(data.begin() + written);
        } else {
            auto curr_mem_data = read_memory(address + written, 8);
            auto to_write_data_ptr = reinterpret_cast<std::byte*>(&qword);
            std::memcpy(to_write_data_ptr, data.begin() + written, remaining_data_size);
            std::memcpy(
                to_write_data_ptr + remaining_data_size, 
                curr_mem_data.data() + remaining_data_size, 
                8 - remaining_data_size
            );
        }
        if (ptrace(PTRACE_POKEDATA, pid_, address + written, qword) < 0) {
            Error::send_errno("Write Mem failed");
        }
        written += 8;
    }
}

int zdb::Process::set_hardware_breakpoint(BreakpointSite::id_type id, VirtualAddr address) {
    return set_hardware_breakpoint(address, StopPointMode::Execute, 1);
}

int zdb::Process::set_hardware_breakpoint(VirtualAddr address, StopPointMode mode, std::size_t size) {
    auto &regs = get_registers();
    auto data_of_controler_dr7 = regs.read_by_id_as<std::uint64_t>(RegisterId::dr7);
    int free_dr_index = find_free_stoppoint_register(data_of_controler_dr7);
    auto free_dr_id = static_cast<int>(RegisterId::dr0) + free_dr_index;
    regs.write_by_id(static_cast<RegisterId>(free_dr_id), address.addr());

    uint64_t mode_flag = encode_hardware_breakpoint_mode(mode);
    uint64_t size_flag = encode_hardware_breakpoint_size(size);
    uint64_t enable_bit = (1 << free_dr_index * 2);
    uint64_t mode_bit = (mode_flag << (free_dr_index * 4 + 16));
    uint64_t size_bit = (size_flag << (free_dr_index * 4 + 18));

    auto mask = (0b11 << (free_dr_index * 2)) | (0b1111 << (free_dr_index * 4 + 16));
    auto data_of_masked_dr7 = data_of_controler_dr7 & ~mask;
    data_of_masked_dr7 |= enable_bit | mode_bit | size_bit;
    regs.write_by_id(RegisterId::dr7, data_of_masked_dr7);
    return free_dr_index;
}

std::variant<zdb::BreakpointSite::id_type, zdb::Watchpoint::id_type> 
zdb::Process::get_lastest_hardward_stoppoint_id() const {
    using RetTy = std::variant<zdb::BreakpointSite::id_type, zdb::Watchpoint::id_type>;
    const Registers &regs = get_registers();
    std::uint64_t data_of_dr6 = regs.read_by_id_as<std::uint64_t>(RegisterId::dr6);
    int dr_index = __builtin_ctzll(data_of_dr6);
    int dr_reg_index = static_cast<int>(RegisterId::dr0) + dr_index;
    VirtualAddr addr_in_dr(regs.read_by_id_as<std::uint64_t>(static_cast<RegisterId>(dr_reg_index)));
    if (breakpoint_sites_.contains_address(addr_in_dr)) {
        const BreakpointSite &bp = breakpoint_sites_.get_by_address(addr_in_dr);
        return RetTy{ std::in_place_index<0>, bp.id()};
    } else {
        const Watchpoint &wp = watchpoints_.get_by_address(addr_in_dr);
        return RetTy{ std::in_place_index<1>, wp.id()};
    }
}

void zdb::Process::clear_hardware_stoppoint(int id) {
    auto &regs = get_registers();
    auto dr_id = static_cast<int>(RegisterId::dr0) + id;
    auto reg_dr_id = static_cast<RegisterId>(dr_id);
    regs.write_by_id(reg_dr_id, 0);

    auto data_of_controler_dr7 = regs.read_by_id_as<std::uint64_t>(RegisterId::dr7);
    auto mask = (0b11 << (id * 2)) | (0b1111 << (id * 4 + 16));
    auto data_of_masked_dr7 = data_of_controler_dr7 & ~mask;
    regs.write_by_id(RegisterId::dr7, data_of_masked_dr7);
}

int zdb::Process::set_watchpoint(Watchpoint::id_type id, VirtualAddr address, StopPointMode mode, std::size_t size) {
    return set_hardware_breakpoint(address, mode, size);
}

zdb::Watchpoint& zdb::Process::create_watchpoint(zdb::VirtualAddr addr, zdb::StopPointMode mode, std::size_t size) {
    if (watchpoints_.contains_address(addr)) {
        zdb::Error::send("Watchpoint already exists as address " + std::to_string(addr.addr()));
    }

    auto point = std::unique_ptr<Watchpoint>(new Watchpoint(*this, addr, mode, size));
    return watchpoints_.push(std::move(point));
}