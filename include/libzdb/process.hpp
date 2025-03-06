#ifndef LIBZDB_PROCESS_HPP
#define LIBZDB_PROCESS_HPP

#include <filesystem>
#include <memory>
#include <sys/types.h>

namespace zdb {

    class Process {
      public:
        static std::unique_ptr<Process> attach(pid_t pid);
        static std::unique_ptr<Process> launch(std::filesystem::path path);

        void resume();
        void wait_on_signal();

        pid_t pid() const {
            return pid_;
        }

      private:
        pid_t pid_ = 0;
    };

} // namespace zdb
#endif // LIBZDB_PROCESS_HPP
