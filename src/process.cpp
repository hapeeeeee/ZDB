#include <libzdb/error.hpp>
#include <libzdb/pipe.hpp>
#include <libzdb/process.hpp>
#include <sys/personality.h>
#include <sys/uio.h>
#include <libzdb/bit.hpp>

namespace {
    void exit_with_perror(zdb::Pipe &pipe, const std::string &prefix) {
        std::string msg = prefix + ": " + std::strerror(errno);
        pipe.write(reinterpret_cast<std::byte *>(msg.data()), msg.size());
        exit(-1);
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
    }
    return proc;
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
    
    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0) {
        Error::send_errno("Continue failed");
    }
    state_ = ProcessState::Running;
}

zdb::StopReason zdb::Process::step() {
    std::optional<BreakpointSite*> to_reenable{nullptr};
    auto pc = get_pc();
    if (breakpoint_sites_.enabled_stoppoint_at_address(pc)) {
        auto &bp = breakpoint_sites_.get_by_address(pc);
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

    if (is_attached_ && state_ == ProcessState::Stopped) {
        read_all_registers();

        auto instr_begin = get_pc() - 1;
        if (stop_reason.info == SIGTRAP and
            breakpoint_sites_.enabled_stoppoint_at_address(instr_begin)) {
            set_pc(instr_begin);
        }
    }

    return stop_reason;
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

zdb::BreakpointSite& zdb::Process::create_breakpoint_site(VirtualAddr address) {
    if (breakpoint_sites_.contains_address(address)) {
        Error::send(
            "Breakpoint site already exists as address " + std::to_string(address.addr())
        );
    }
    auto site = std::unique_ptr<BreakpointSite>(
        new BreakpointSite(*this, address)
    );
    return breakpoint_sites_.push(std::move(site));
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

std::vector<std::byte> zdb::Process::read_memory_without_trap(VirtualAddr addr, std::size_t amount) { 
    auto mem_data = read_memory(addr, amount);
    std::vector<BreakpointSite&> sites = breakpoint_sites_.get_in_region(addr, addr + amount);
    for (auto site : sites) {
        if (!site.is_enabled()) {
            continue;
        }
        auto offset = site.address() - addr.addr();
        mem_data[offset.addr()] = site.saved_data();   
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
