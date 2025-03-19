#include <catch2/catch_test_macros.hpp>
#include <fstream>
#include <libzdb/error.hpp>
#include <libzdb/process.hpp>
#include <libzdb/pipe.hpp>
#include <string_view>
#include <libzdb/bit.hpp>
#include <libzdb/pipe.hpp>
#include <stdio.h>
#include <regex>
#include <elf.h>

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

namespace {
    /// 由于可执行程序编译时指定了`-pie`, 所以可执行程序的磁盘文件的加载地址和实际偏移不同，
    /// 所以需要计算可执行程序的代码段被加载时的误差
    /// 计算方式是：代码段的加载误差 = 代码段的加载地址 - 代码段在磁盘文件中的实际偏移 (get_section_load_bias)
    /// 然后计算：  入口指令的磁盘实际偏移 = 入口指令的磁盘地址 - 代码段的加载误差 (get_entry_point_offset)
    /// 由于我们的调试器在launch子程序时设置了`personality(ADDR_NO_RANDOMIZE)`,
    /// 所以可执行程序的加载地址是固定的，不存在指令加载地址和内存地址不同的情况
    /// 所以可以计算出可执行程序的入口指令的内存地址相对于程序加载内存地址的偏移 
    /// 计算方式是：入口指令的内存地址 = 程序的起始内存地址 + 入口指令的磁盘实际偏移 (get_load_address)
    /// img desc: docs/breakpoint_site_set/testcase_for_calu_breakpointsite_set.png

    std::int64_t get_section_load_bias(std::filesystem::path path, Elf64_Addr vaddr) {
        auto command = std::string("readelf -WS ") + path.string();
        auto fd = popen(command.c_str(), "r");
        if (!fd) {
            zdb::Error::send_errno("Failed to run readelf");
        }

        std::regex text_regex(R"(PROGBITS\s+(\w+)\s+(\w+)\s+(\w+))");
        char *line = nullptr;
        size_t len = 0;
        while (getline(&line, &len, fd) != -1) {
            std::cmatch match;
            if (std::regex_search(line, match, text_regex)) {
                auto address = std::stol(match[1], nullptr, 16);
                auto offset = std::stol(match[2], nullptr, 16);
                auto size = std::stol(match[3], nullptr, 16);
                if (address <= vaddr && vaddr < address + size) {
                    pclose(fd);
                    free(line);
                    return address - offset;
                }
            }
            free(line);
            line = nullptr;
        }
        pclose(fd);
        zdb::Error::send("Failed to find section for address");
    }

    std::int64_t get_entry_point_offset(std::filesystem::path path) {
        std::ifstream elf_file(path);
        Elf64_Ehdr header;
        elf_file.read(reinterpret_cast<char*>(&header), sizeof(header));
        auto entry_file_address = header.e_entry;
        return entry_file_address - get_section_load_bias(path, entry_file_address);
    }

    VirtualAddr get_load_address(pid_t pid, std::int64_t offset) {
        std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
        std::regex map_regex (R"((\w+)-\w+ ..(.). (\w+))");
        std::string data;
        while (std::getline(maps, data)) {
            std::smatch groups;
            std::regex_search(data, groups, map_regex);
            if (groups[2] == 'x') {
                // get virtual address of code section in memory
                auto code_section_start_address_in_memory = std::stol(groups[1], nullptr, 16);
                // code section offset relative to process start in memory
                auto code_section_offset_in_memory = std::stol(groups[3], nullptr, 16); 
                int64_t process_start_address_in_memory = code_section_start_address_in_memory - code_section_offset_in_memory; 
                return VirtualAddr(offset + process_start_address_in_memory);
            }
        }
        zdb::Error::send("Could not find load address");
    }
}

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

TEST_CASE("Breakpoint site can be created", "[breakpoint]") {
    auto proc = Process::launch("bin/run_endlessly");
    auto &breakpoint_site = proc->create_breakpoint_site(VirtualAddr{42});
    REQUIRE(breakpoint_site.address().addr() == 42);
}

TEST_CASE("Breakpoint ids can increase", "[breakpoint]") {
    auto proc = Process::launch("bin/run_endlessly");
    auto &breakpoint_site1 = proc->create_breakpoint_site(VirtualAddr{42});
    auto &breakpoint_site2 = proc->create_breakpoint_site(VirtualAddr{43});
    auto &breakpoint_site3 = proc->create_breakpoint_site(VirtualAddr{44});
    auto &breakpoint_site4 = proc->create_breakpoint_site(VirtualAddr{45});

    REQUIRE(breakpoint_site2.id() == breakpoint_site1.id() + 1);
    REQUIRE(breakpoint_site3.id() == breakpoint_site1.id() + 2);
    REQUIRE(breakpoint_site4.id() == breakpoint_site1.id() + 3);
}

TEST_CASE("Breakpoint site can be find", "[breakpoint]") {
    auto proc = Process::launch("bin/run_endlessly");
    auto &breakpoint_site1 = proc->create_breakpoint_site(VirtualAddr{42});
    auto &breakpoint_site2 = proc->create_breakpoint_site(VirtualAddr{43});
    auto &breakpoint_site3 = proc->create_breakpoint_site(VirtualAddr{44});
    auto &breakpoint_site4 = proc->create_breakpoint_site(VirtualAddr{45});

    REQUIRE(proc->breakpoint_sites().contains_address(VirtualAddr{42}));
    auto &found_site1 = proc->breakpoint_sites().get_by_address(VirtualAddr{42});
    REQUIRE(found_site1.at_address(breakpoint_site1.address()));

    REQUIRE(proc->breakpoint_sites().contains_id(breakpoint_site2.id()));
    auto &found_site2 = proc->breakpoint_sites().get_by_id(breakpoint_site2.id());
    REQUIRE(found_site2.address().addr() == 43);

    const auto &const_proc = *proc;
    REQUIRE(const_proc.breakpoint_sites().contains_address(VirtualAddr{44}));
    auto &found_site3 = const_proc.breakpoint_sites().get_by_address(VirtualAddr{44});
    REQUIRE(found_site3.at_address(breakpoint_site3.address()));

    REQUIRE(const_proc.breakpoint_sites().contains_id(breakpoint_site4.id()));
    auto &found_site4 = const_proc.breakpoint_sites().get_by_id(breakpoint_site4.id());
    REQUIRE(found_site4.address().addr() == 45);
}

TEST_CASE("Breakpoint site can not be find", "[breakpoint]") {
    auto proc = Process::launch("bin/run_endlessly");
    const auto &const_proc = *proc;

    REQUIRE_THROWS_AS(proc->breakpoint_sites().get_by_address(VirtualAddr{42}), zdb::Error);
    REQUIRE_THROWS_AS(proc->breakpoint_sites().get_by_id(42), zdb::Error);
    REQUIRE_THROWS_AS(const_proc.breakpoint_sites().get_by_address(VirtualAddr{42}), zdb::Error);
    REQUIRE_THROWS_AS(const_proc.breakpoint_sites().get_by_id(42), zdb::Error);
}

TEST_CASE("Breakpoint site list size and emptiness", "[breakpoint]") {
    auto proc = Process::launch("bin/run_endlessly");
    const auto& cproc = proc;

    REQUIRE(proc->breakpoint_sites().empty());
    REQUIRE(proc->breakpoint_sites().size() == 0);
    REQUIRE(cproc->breakpoint_sites().empty());
    REQUIRE(cproc->breakpoint_sites().size() == 0);

    proc->create_breakpoint_site(VirtualAddr{ 42 });
    REQUIRE(!proc->breakpoint_sites().empty());
    REQUIRE(proc->breakpoint_sites().size() == 1);
    REQUIRE(!cproc->breakpoint_sites().empty());
    REQUIRE(cproc->breakpoint_sites().size() == 1);

    proc->create_breakpoint_site(VirtualAddr{ 43 });
    REQUIRE(!proc->breakpoint_sites().empty());
    REQUIRE(proc->breakpoint_sites().size() == 2);
    REQUIRE(!cproc->breakpoint_sites().empty());
    REQUIRE(cproc->breakpoint_sites().size() == 2);
}

TEST_CASE("Can iterate breakpoint sites", "[breakpoint]") {
    auto proc = Process::launch("bin/run_endlessly");
    const auto& cproc = proc;

    proc->create_breakpoint_site(VirtualAddr{ 42 });
    proc->create_breakpoint_site(VirtualAddr{ 43 });
    proc->create_breakpoint_site(VirtualAddr{ 44 });
    proc->create_breakpoint_site(VirtualAddr{ 45 });

    /// ???
    proc->breakpoint_sites().for_each(
    [addr = 42](auto& site) mutable {
            REQUIRE(site->address().addr() == addr++);
        }
    );

    cproc->breakpoint_sites().for_each(
    [addr = 42](auto& site) mutable {
            REQUIRE(site->address().addr() == addr++);
        }
    );
}

TEST_CASE("Can remove breakpoint sites", "[breakpoint]") {
    auto proc = Process::launch("bin/run_endlessly");
    auto& site = proc->create_breakpoint_site(VirtualAddr{ 42 });
    proc->create_breakpoint_site(VirtualAddr{ 43 });
    REQUIRE(proc->breakpoint_sites().size() == 2);
    proc->breakpoint_sites().remove_by_id(site.id());
    proc->breakpoint_sites().remove_by_address(VirtualAddr{ 43 });
    REQUIRE(proc->breakpoint_sites().empty());
}

TEST_CASE("Breakpoint site on address work", "[breakpoint]") {
    bool close_on_exec = false;
    zdb::Pipe pipe(close_on_exec);
    auto proc = Process::launch("bin/hello_zdb", true, pipe.get_write());
    pipe.close_write();
    auto file_actual_offset_of_entry_code_in_disk = get_entry_point_offset("bin/hello_zdb");
    auto memory_load_address_of_entry_code = get_load_address(proc->pid(), file_actual_offset_of_entry_code_in_disk);
    proc->create_breakpoint_site(memory_load_address_of_entry_code).enable();
    proc->resume();
    StopReason reason = proc->wait_on_signal();
    REQUIRE(reason.reason == ProcessState::Stopped);
    REQUIRE(reason.info == SIGTRAP);
    REQUIRE(proc->get_pc() == memory_load_address_of_entry_code);

    proc->resume();
    reason = proc->wait_on_signal();
    auto data = pipe.read();
    REQUIRE(to_string_view(data) == "Hello, ZDB!\n");
}