#include "libzdb/process.hpp"
#include "libzdb/error.hpp"
#include "libzdb/pipe.hpp"

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
    if (pid_ != 0) {
        int status;
        if (state_ == ProcessState::Running) {
            kill(pid_, SIGSTOP);
            waitpid(pid_, &status, 0);
        }
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        kill(pid_, SIGCONT);

        if (terminate_on_end_) {
            kill(pid_, SIGKILL);
            waitpid(pid_, &status, 0);
        }
    }
}

std::unique_ptr<zdb::Process> zdb::Process::attach(pid_t pid) {
    if (pid <= 0) {
        Error::send("Invalid PID");
    }
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        Error::send_errno("Attach failed");
    }

    std::unique_ptr<Process> proc(new Process(pid, /*terminate_on_end=*/false));
    proc->wait_on_signal();
    return proc;
}

std::unique_ptr<zdb::Process> zdb::Process::launch(std::filesystem::path path) {
    zdb::Pipe channel(/*close_on_exec=*/true);
    pid_t pid = fork();
    if (pid < 0) {
        Error::send_errno("Fork failed");
    } else if (pid == 0) {
        // Now in child process, execute the debuggee
        channel.close_read();
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
            exit_with_perror(channel, "Trace failed");
        }
        if (execlp(path.c_str(), path.c_str(), nullptr) < 0) {
            exit_with_perror(channel, "Exec failed");
        }
    }

    channel.close_write();
    std::vector<std::byte> msg = channel.read();
    channel.close_read();

    if (msg.size() > 0) {
        waitpid(pid, nullptr, 0);
        auto chars = reinterpret_cast<char *>(msg.data());
        zdb::Error::send(std::string(chars, chars + msg.size()));
    }

    std::unique_ptr<Process> proc(new Process(pid, /*terminate_on_end=*/true));
    proc->wait_on_signal();
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
