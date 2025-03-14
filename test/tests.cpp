#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <libzdb/error.hpp>
#include <libzdb/process.hpp>
#include <libzdb/pipe.hpp>
#include <string_view>
#include <libzdb/bit.hpp>
#include <libzdb/pipe.hpp>

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

TEST_CASE("Write register works", "[register]") {
    zdb::Pipe pipe(/*close_on_exec=*/true);
    auto proc = Process::launch("bin/reg_write", true, pipe.get_write());
    proc->resume();
    proc->wait_on_signal();

    zdb::Registers& regs = proc->get_registers();
    regs.write_by_id(RegisterId::rsi, 0xcafecafe);
    proc->resume();
    proc->wait_on_signal();
    auto result = pipe.read();
    REQUIRE(to_string_view(result) == "0xcafecafe");

    regs.write_by_id(RegisterId::mm0, 0xba5eba11);
    proc->resume();
    proc->wait_on_signal();
    result = pipe.read();
    REQUIRE(to_string_view(result) == "0xba5eba11");

    regs.write_by_id(RegisterId::xmm0, 42.24);
    proc->resume();
    proc->wait_on_signal();
    result = pipe.read();
    REQUIRE(to_string_view(result) == "42.24");

    regs.write_by_id(RegisterId::st0, 42.24l);
    regs.write_by_id(RegisterId::fsw, std::uint16_t(0b0011100000000000));
    regs.write_by_id(RegisterId::ftw, std::uint16_t(0b0011111111111111));
    proc->resume();
    proc->wait_on_signal();
    result = pipe.read();
    REQUIRE(to_string_view(result) == "42.24");
}


TEST_CASE("Read register works", "[register]") {
    auto proc = Process::launch("bin/reg_read");
    auto &regs = proc->get_registers();
    regs.write_by_id(RegisterId::r13, 0xcafecafe);
    proc->resume();
    proc->wait_on_signal();
    auto r13 = regs.read_by_id_as<std::uint64_t>(RegisterId::r13);
    REQUIRE(r13 == 0xcafecafe);

    proc->resume();
    proc->wait_on_signal();
    auto r13b = regs.read_by_id_as<std::uint8_t>(RegisterId::r13b);
    REQUIRE(r13b == 42);
    
    proc->resume();
    proc->wait_on_signal();
    auto mm0 = regs.read_by_id_as<byte64>(RegisterId::mm0);
    REQUIRE(mm0 == as_byte64(0xba5eba11ull));
    
    proc->resume();
    proc->wait_on_signal();
    auto xmm0 = regs.read_by_id_as<byte128>(RegisterId::xmm0);
    REQUIRE(xmm0 == as_byte128(64.125));

    proc->resume();
    proc->wait_on_signal();
    auto st0 = regs.read_by_id_as<long double>(RegisterId::st0);
    REQUIRE(st0 == 64.125L);

}
