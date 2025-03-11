#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <libzdb/error.hpp>
#include <libzdb/process.hpp>
using namespace zdb;

namespace {
    bool process_exists(pid_t pid) {
        int status = kill(pid, 0);
        return status == 0 || errno == EPERM;
    }

    char get_process_status(pid_t pid) {
        std::string status_file = "/proc/" + std::to_string(pid) + "/stat";
        std::ifstream status_stream(status_file);
        std::string line;
        std::getline(status_stream, line);
        auto index_of_last_parenthesis = line.find_last_of(')');
        auto index_of_status_indicator = index_of_last_parenthesis + 2;
        return line[index_of_status_indicator];
    }
} // namespace

TEST_CASE("Process::launch Success", "[process]") {
    auto proc = Process::launch("yes");
    REQUIRE(process_exists(proc->pid()));
}

TEST_CASE("Process::launch No such program", "[process]") {
    REQUIRE_THROWS_AS(Process::launch("nonexistent"), zdb::Error);
}

TEST_CASE("Process::attach Success", "[process]") {
    auto target = Process::launch("bin/run_endlessly", false);
    auto proc   = Process::attach(target->pid());
    REQUIRE(get_process_status(target->pid()) == 't');
}

TEST_CASE("Process::attach invalid PID", "[process]") {
    REQUIRE_THROWS_AS(Process::attach(0), zdb::Error);
}

TEST_CASE("Process::resume Success", "[process]") {
    {
        auto proc = Process::launch("bin/run_endlessly");
        proc->resume();
        auto status  = get_process_status(proc->pid());
        auto success = status == 'R' || status == 'S';
        REQUIRE(success);
    }

    {
        auto target = Process::launch("bin/run_endlessly", false);
        auto proc   = Process::attach(target->pid());
        proc->resume();
        auto status  = get_process_status(target->pid());
        auto success = status == 'R' || status == 'S';
        REQUIRE(success);
    }
}

TEST_CASE("Process::resume already terminated", "[process]") {
    auto proc = Process::launch("bin/end_immediately");
    proc->resume();
    proc->wait_on_signal();
    REQUIRE_THROWS_AS(proc->resume(), zdb::Error);
}
