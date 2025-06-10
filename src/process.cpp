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
        // PTRACE_O_TRACESYSGOOD: 在系统调用入口或出口（PTRACE_SYSCALL）时，区分 真正的信号 和 系统调用停止
        // PTRACE_O_TRACECLONE: 每当被调试进程调用clone syscall创建一个线程或进程，ptrace 会自动中断并通知调试器。
        if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE) < 0) {
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

zdb::StopReason::StopReason(pid_t tid, int wait_status): tid(tid) {
    if ((wait_status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
        trap_type = TrapType::Clone;
    }

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

void zdb::Process::resume(std::optional<pid_t> otid) {
    int tid = otid.value_or(current_thread_);
    step_over_breakpoint(tid);
    send_continue(tid);
}

void zdb::Process::step_over_breakpoint(pid_t tid) {
    VirtualAddr pc = get_pc(tid);
    if (breakpoint_sites_.enabled_stoppoint_at_address(pc)) {
        auto &bp = breakpoint_sites_.get_by_address(pc);
        bp.disable();

        swallow_pending_sigstop(tid);
        if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) < 0) {
            Error::send_errno("Single Step after breakpoint failed");
        }

        int status;
        if (waitpid(tid, &status, 0) < 0) {
            Error::send_errno("Wait after single step failed");
        }
        bp.enable();
    } 
}

void zdb::Process::send_continue(pid_t tid) {
    auto ptrace_req = 
        syscall_catch_policy_.get_mode() == SyscallCatchPolicy::CatchMode::None ?
            PTRACE_CONT : 
            PTRACE_SYSCALL;
    if (ptrace(ptrace_req, tid, nullptr, nullptr) < 0) {
        Error::send_errno("Continue failed");
    }
    threads_.at(tid).state = ProcessState::Running;
    state_ = ProcessState::Running;
}



bool zdb::Process::should_resume_from_syscall(const StopReason &reason) {
    if (syscall_catch_policy_.get_mode() == SyscallCatchPolicy::CatchMode::Some) {
        const std::vector<int> &to_catch = syscall_catch_policy_.get_to_catch();
        auto found = std::find(to_catch.begin(), to_catch.end(), reason.syscall_info->syscall_id);
        if (found == end(to_catch)) {
            return true;
        }
    }
    return false;
}

void zdb::Process::stop_running_threads() {
    for (auto& [tid, thread] : threads_) {
        if (thread.state != ProcessState::Running) continue;

        if (!thread.pending_sigstop) tgkill(pid_, tid, SIGSTOP);

        int wait_status;
        waitpid(tid, &wait_status, 0);

        StopReason thread_stop_reason(tid, wait_status);

        // 如果进程是由于信号而停止的，那么我们需要考虑两种可能性。
        // 如果那个信号不是SIGSTOP，那么这个线程上肯定有一个挂起的SIGSTOP，所以我们记录它。
        // 如果信号是SIGSTOP，但在这之前已经有一个被记录为挂起的SIGSTOP，那么我们假设这就是我们正在等待的SIGSTOP，
        // 并重置pending_sigstop。
        if (thread_stop_reason.reason == ProcessState::Stopped) {
            if (thread_stop_reason.info != SIGSTOP) {
                thread.pending_sigstop = true;
            }
            else if (thread.pending_sigstop) {
                thread.pending_sigstop = false;
            }
        }

        thread_stop_reason = handle_signal(
            thread_stop_reason,
            false // 不是被调试进程里的原始信号，而是当前函数通过tgkill触发的信号
        ).value_or(thread_stop_reason);

        threads_.at(tid).reason = thread_stop_reason;
        threads_.at(tid).state = thread_stop_reason.reason;
    }
}

void zdb::Process::resume_all_threads() {
    for (auto& [tid, _] : threads_) {
        step_over_breakpoint(tid);
    }
    for (auto& [tid, _] : threads_) {
        send_continue(tid);
    }
}

std::optional<zdb::StopReason> zdb::Process::cleanup_exited_threads(pid_t main_stop_tid) {
    std::vector<pid_t> to_remove;
    std::optional<StopReason> to_report;

    for (auto& [tid, thread] : threads_) {
        if (tid != main_stop_tid && 
            (thread.state == ProcessState::Exited || 
            thread.state == ProcessState::Terminated)
        ) {
            report_thread_lifecycle_event(thread.reason);
            to_remove.push_back(tid);
            if (tid == pid_) {
                to_report = thread.reason;
            }
        } 
    }

    for (auto tid : to_remove) {
        threads_.erase(tid);
    }

    return to_report;
}

void zdb::Process::report_thread_lifecycle_event(const StopReason& reason) {
    if (thread_lifecycle_callback_) {
        thread_lifecycle_callback_(reason);
    }
    if (target_) {
        target_->notify_thread_lifecycle_event(reason);
    }
}

// 负责处理wait_on_signal捕获的信号和我们人为地停止所有线程时产生的信号
// 
std::optional<zdb::StopReason> zdb::Process::handle_signal(StopReason reason, bool is_main_stop) {
    int tid = reason.tid;

    if (is_main_stop && reason.trap_type && reason.trap_type.value() == TrapType::Clone) {
        return std::nullopt;
    }

    if (is_attached_ && reason.reason == ProcessState::Stopped) {
        if (!threads_.count(tid)) {
            threads_.emplace(tid, ThreadState{ tid, Registers(*this, tid) });
            report_thread_lifecycle_event(reason);
            if (is_main_stop) {
                return std::nullopt;
            }
        }
        
        if (threads_.at(tid).pending_sigstop && reason.info == SIGSTOP) {
            threads_.at(tid).pending_sigstop = false;
            return std::nullopt;
        }

        read_all_registers(tid);
        augment_trap_type(reason);

        if (reason.info == SIGTRAP) {
            VirtualAddr instr_begin = get_pc(tid) - 1;
            if (reason.trap_type == TrapType::SoftwareBreakpoint
                && breakpoint_sites_.enabled_stoppoint_at_address(instr_begin)
            ) {
                set_pc(instr_begin, tid);
                BreakpointSite& bp = breakpoint_sites_.get_by_address(instr_begin);
                if (bp.parent_) {
                    bool should_restart = bp.parent_->notify_hit();
                    if (should_restart && is_main_stop) {
                        return std::nullopt;
                    }
                }
            }
            else if (reason.trap_type == TrapType::HardwareBreakpoint) {
                auto id = get_lastest_hardward_stoppoint_id(tid);
                if (id.index() == 1) {
                    watchpoints_.get_by_id(std::get<1>(id)).update_data();
                }
            }
            else if (reason.trap_type == TrapType::Syscall
                && is_main_stop
                && should_resume_from_syscall(reason)
            ) {
                return std::nullopt;
            }
        }
        if (target_) target_->notify_stop(reason);
    }
    return reason;
}

zdb::StopReason zdb::Process::step(std::optional<pid_t> otid) {
    auto tid = otid.value_or(current_thread_);
    std::optional<BreakpointSite*> to_reenable;
    VirtualAddr pc = get_pc(tid);
    if (breakpoint_sites_.enabled_stoppoint_at_address(pc)) {
        BreakpointSite &bp = breakpoint_sites_.get_by_address(pc);
        bp.disable();
        to_reenable = &bp;
    }

    swallow_pending_sigstop(tid);
    if (ptrace(PTRACE_SINGLESTEP, tid, nullptr, nullptr) < 0) {
        Error::send_errno("Single Step failed");
    }
    
    StopReason stop_reason = wait_on_signal(tid);
    if (to_reenable) {
        to_reenable.value()->enable();
    }
    return stop_reason;
}

void zdb::Process::swallow_pending_sigstop(pid_t tid) {
    if (threads_.at(tid).pending_sigstop) {
        // SIGSTOP 信号的处理会有以下特点：
        //  - SIGSTOP 是一个同步信号
        //  - 系统调用本身是一个原子操作
        //  - 当进程正在执行系统调用时，SIGSTOP 会被推迟到系统调用完成后才处理
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        waitpid(tid, nullptr, 0);
        threads_.at(tid).pending_sigstop = false;
    }
}

// 需要处理以下情况
//  - 收到不该报告的信号：动态库加载、线程启动
//      让线程继续执行，不报告
//  - 收到不该报告的信号，但存在其他线程已经停止（还未收到该线程停止信号）
//      让线程继续执行，不报告
//  - 收到该报告的信号，其他所有线程还在执行
//      给其他所有线程发送SIGSTOP， 等待他们停止执行，然后报告给用户
//  - 收到该报告的信号，但存在其他线程已经停止（还未收到该线程停止信号）：多个线程同时命中断点，还有线程已经退出
//      向所有运行线程发送SIGSTOP，使用waitpid来等待它们全部停止。我们将检查waitpid返回的状态，
//      以查看每个线程停止的真实的原因。如果线程退出，我们将从跟踪线程列表中删除它。如果它由于SIGSTOP而停止，
//      我们将假设它是我们发送的SIGSTOP。如果它由于其他信号而停止（类似SIGTRAP），我们将记录该信号有一个挂起的SIGSTOP。
//      然后，下一次该线程收到一个信号时，如果它是一个SIGSTOP，我们将重新启动该线程并继续执行，就像什么都没有发生一样。
//      如果某个线程由于一个我们不应该报告的信号而停止，我们无论如何都会报告它，因为我们正在全停止模式下操作，不应该重新启动该线程
//  - 主线程退出
//      主线程（其TID与进程的PID匹配的线程）退出，我们将认为整个进程已经退出。（实际实现并不一定是这种情况，但这更加简单）
//  - 非主线程退出
//      打印一条通知消息
//  - 用户为存在挂起SIGSTOP的线程请求单步执行
//      在单步执行之前检查线程上是否有挂起的SIGSTOP。如果存在，我们将恢复线程，并在发送PTRACE_SINGLESTEP请求
//      之前调用waitpid来消耗信号。在某些情况下，这种方法会做错误的事情。例如，如果线程单步执行不应该报告的系统调用，
//      它将被发送一个PTRACE_CONT而不是PTRACE_SINGLESTEP。然而，这是非常罕见的情况，所以我们将选择更简单的实现。
zdb::StopReason zdb::Process::wait_on_signal(pid_t to_await) {
    int wait_status;
    int options = __WALL;
    pid_t tid;              // 返回线程的线程ID
    if ((tid = waitpid(to_await, &wait_status, options)) < 0) {
        Error::send_errno("Wait signal failed");
    }

    StopReason stop_reason(tid, wait_status);
    std::optional<StopReason> final_reason = handle_signal(stop_reason, true);
    if (!final_reason) {
        resume(tid);
        return wait_on_signal(to_await);
    }

    stop_reason = *final_reason;
    ThreadState& thread = threads_.at(tid);
    thread.reason = stop_reason;
    thread.state = stop_reason.reason;

    if (stop_reason.reason == ProcessState::Exited ||
        stop_reason.reason == ProcessState::Terminated
    ) {
        report_thread_lifecycle_event(stop_reason);
        if (tid == pid_) {  // 如果是主线程则直接返回
            state_ = stop_reason.reason;
            return stop_reason;
        }
        else {              // 如果是某个子线程返回则继续监听
            return wait_on_signal(-1);
        }
    }
    
    // At this point, we have a signal representing a stop we should report back
    // to the user, so we’ll stop all running threads, clean up any that exited, 
    // set the current state and active thread of the process, and then return.
    stop_running_threads();
    stop_reason = cleanup_exited_threads(tid).value_or(stop_reason);
    state_ = stop_reason.reason;
    current_thread_ = tid;
    return stop_reason;

    // if (!is_attached_ || state_ != ProcessState::Stopped) {
    //     return stop_reason;
    // }

    // read_all_registers(to_await);
    // augment_trap_type(stop_reason);
    // if (stop_reason.info != SIGTRAP) {
    //     return stop_reason;
    // }

    // auto instr_begin = get_pc() - 1;
    // if (stop_reason.trap_type == TrapType::SoftwareBreakpoint 
    //     && breakpoint_sites_.enabled_stoppoint_at_address(instr_begin)
    // ) {
    //     set_pc(instr_begin);

    //     auto& bp = breakpoint_sites_.get_by_address(instr_begin);
    //     if (bp.parent_) {
    //         bool should_restart = bp.parent_->notify_hit();
    //         if (should_restart) {
    //             resume();
    //             return wait_on_signal();
    //         }
    //     }
    // } 
    // else if (stop_reason.trap_type == TrapType::HardwareBreakpoint) {
    //     auto id = get_lastest_hardward_stoppoint_id();
    //     if (id.index() == 1) {
    //         watchpoints_.get_by_id(std::get<1>(id)).update_data();
    //     }
    // }
    // else if (stop_reason.trap_type == TrapType::Syscall) {
    //     stop_reason = resume_from_untrack_syscall(stop_reason);
    // }

    // if (target_) {
    //     target_->notify_stop(stop_reason);
    // } 
    
    // return stop_reason;
}

void zdb::Process::augment_trap_type(StopReason &reason) {
    pid_t tid = reason.tid;
    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) < 0) {
        Error::send_errno("Get signal info failed");
    }

    // Now that we’ve enabled `PTRACE_O_TRACESYSGOOD` option, 
    // the signal number will have its eighth bit set if the SIGTRAP came from a syscall. 
    // This means we can use signal ==  to check whether we’re trapped by a syscall. 
    if (reason.info == (SIGTRAP | 0x80)) {
        auto &syscall_info = reason.syscall_info.emplace();
        auto &regs = get_registers(tid);

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

zdb::VirtualAddr zdb::Process::get_pc(std::optional<pid_t> otid) const {
    return VirtualAddr{ get_registers(otid).read_by_id_as<std::uint64_t>(RegisterId::rip) };
}

void zdb::Process::set_pc(VirtualAddr address, std::optional<pid_t> otid) {
    get_registers(otid).write_by_id(RegisterId::rip, address.addr());
}

zdb::Registers& zdb::Process::get_registers(std::optional<pid_t> otid) {
    auto tid = otid.value_or(current_thread_);
    return threads_.at(tid).regs;
}

const zdb::Registers& zdb::Process::get_registers(std::optional<pid_t> otid) const {
    return const_cast<Process*>(this)->get_registers(otid);
}

void zdb::Process::read_all_registers(pid_t tid) {
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &get_registers(tid).data_.regs) < 0) {
        Error::send_errno("Read registers failed");
    }
    if (ptrace(PTRACE_GETFPREGS, tid, nullptr, &get_registers(tid).data_.i387) < 0) {
        Error::send_errno("Read FPU registers failed");
    }

    for (int i = 0; i < 8; ++i) {
        auto id = static_cast<int>(RegisterId::dr0) + i;
        auto info = find_register_info_by_id(static_cast<RegisterId>(id));
        errno = 0;
        std::int64_t data = ptrace(PTRACE_PEEKUSER, tid, info.offset, nullptr); 
        if (errno != 0) {
            zdb::Error::send_errno("Could not read debug register");
        }
        get_registers(tid).data_.u_debugreg[i] = data;
    }
}

void zdb::Process::write_user_area(
    std::size_t offset, 
    std::uint64_t data,
    std::optional<pid_t> otid
) {
    int tid = otid.value_or(current_thread_);
    if (ptrace(PTRACE_POKEUSER, tid, offset, data) < 0) {
        Error::send_errno("Write user area failed");
    }
}

void zdb::Process::write_fprs(const user_fpregs_struct& fprs, std::optional<pid_t> otid) {
    int tid = otid.value_or(current_thread_);
    if (ptrace(PTRACE_SETFPREGS, tid, nullptr, &fprs) < 0) {
        Error::send_errno("Could not write floating point registers");
    }
}

void zdb::Process::write_gprs(const user_regs_struct& gprs, std::optional<pid_t> otid) {
    int tid = otid.value_or(current_thread_);
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &gprs) < 0) {
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

    for (auto& [tid, _] : threads_) {
        if (tid == current_thread_) continue;
        auto& other_regs = get_registers(tid);
        other_regs.write_by_id(static_cast<RegisterId>(free_dr_id), address.addr());
        other_regs.write_by_id(RegisterId::dr7, data_of_masked_dr7);
    }

    return free_dr_index;
}

std::variant<zdb::BreakpointSite::id_type, zdb::Watchpoint::id_type> 
zdb::Process::get_lastest_hardward_stoppoint_id(std::optional<pid_t> otid) const {
    using RetTy = std::variant<zdb::BreakpointSite::id_type, zdb::Watchpoint::id_type>;
    const Registers &regs = get_registers(otid);
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

    for (auto& [tid, _] : threads_) {
        if (tid == current_thread_) continue;
        auto& other_regs = get_registers(tid);
        other_regs.write_by_id(static_cast<RegisterId>(id), 0);
        other_regs.write_by_id(RegisterId::dr7, data_of_masked_dr7);
    }
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

void zdb::Process::populate_existing_threads() {
    auto path = "/proc/" + std::to_string(pid_) + "/task";
    for (auto& entry : std::filesystem::directory_iterator(path)) {
        int tid = std::stoi(entry.path().filename().string());
        threads_.emplace(tid, ThreadState{ tid, Registers(*this, tid) });
    }
}