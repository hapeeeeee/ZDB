#include <libzdb/target.hpp>
#include <libzdb/elf.hpp>


namespace {
    std::unique_ptr<zdb::ELF> create_loaded_elf(
        const zdb::Process &process, 
        const std::filesystem::path &path
    ) {
        auto auxv = process.get_auxv();
        std::unique_ptr<zdb::ELF> elf = std::make_unique<zdb::ELF>(path);
        elf->notify_loaded(zdb::VirtualAddr(
            // load_bias_ = 
            //  actual memory address of the program entry point 
            //  - load address in elf phisical elf file
            auxv[AT_ENTRY] - elf->get_elf_header().e_entry
        ));

        return elf;
    } 
}

std::unique_ptr<zdb::Target> zdb::Target::launch(
    std::filesystem::path path,
    std::optional<int> stdout_fd
) {
    auto process = Process::launch(path, true, stdout_fd);
    auto elf = create_loaded_elf(*process, path);
    return std::unique_ptr<Target>(
        new Target(std::move(process), std::move(elf))
    );
}

std::unique_ptr<zdb::Target> zdb::Target::attach(pid_t pid) {
    // We need a way to find the ELF file associated with a given PID.
    // The /proc/<pid>/exe file is a symbolic link to the executable 
    // for the given process.
    auto elf_path = std::filesystem::path("/proc") / std::to_string(pid) / "exe";
    auto proc = Process::attach(pid);
    auto obj = create_loaded_elf(*proc, elf_path);
    return std::unique_ptr<Target>(
        new Target(std::move(proc), std::move(obj))
    );
}
