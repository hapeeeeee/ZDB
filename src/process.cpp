#include <libzdb/error.hpp>
#include <libzdb/pipe.hpp>
#include <libzdb/process.hpp>

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

std::unique_ptr<zdb::Process> zdb::Process::launch(std::filesystem::path path, bool debug) {
    zdb::Pipe channel(/*close_on_exec=*/true);
    pid_t pid = fork();
    if (pid < 0) {
        Error::send_errno("Fork failed");
    } else if (pid == 0) {
        // Now in child process, execute the debuggee
        channel.close_read();
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
    if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0) {
        Error::send_errno("Continue failed");
    }
    state_ = ProcessState::Running;
}

zdb::StopReason zdb::Process::wait_on_signal() {
    int wait_status;
    if (waitpid(pid_, &wait_status, 0) < 0) {
        Error::send_errno("Wait signal failed");
    }
    StopReason stop_reason(wait_status);
    state_ = stop_reason.reason;
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
        
    }
}


void zdb::Process::write_user_area(std::size_t offset, std::uint64_t data) {
    if (ptrace(PTRACE_POKEUSER, pid_, offset, data) < 0) {
        Error::send_errno("Write user area failed");
    }
}