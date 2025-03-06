#ifndef LIBZDB_PROCESS_HPP
#define LIBZDB_PROCESS_HPP

#include <filesystem>
#include <iostream>
#include <memory>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

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
        Process()                           = delete;
        Process(const Process &)            = delete;
        Process &operator=(const Process &) = delete;
        ~Process();

      public:
        static std::unique_ptr<Process> attach(pid_t pid);
        static std::unique_ptr<Process> launch(std::filesystem::path path);

        void resume();
        StopReason wait_on_signal();

        pid_t pid() const {
            return pid_;
        }

        ProcessState state() const {
            return state_;
        }

      private:
        pid_t pid_             = 0;
        bool terminate_on_end_ = true;
        ProcessState state_    = ProcessState::Stopped;

      private:
        Process(pid_t pid, bool terminate_on_end) : pid_(pid), terminate_on_end_(terminate_on_end) {
        }
    };
} // namespace zdb

#endif // LIBZDB_PROCESS_HPP
