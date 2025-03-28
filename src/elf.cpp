#include <libzdb/elf.hpp>
#include <fcntl.h>
#include <sys/stat.h>
#include <libzdb/error.hpp>
#include <unistd.h>
#include <sys/mman.h>
#include <libzdb/bit.hpp>

namespace zdb {
    ELF::ELF(const std::filesystem::path &path): path_(path) {
        if (fd_ = open(path.c_str(), O_RDONLY) < 0) {
            Error::send_errno("open file failed");
        }

        struct stat file_stat;
        if (fstat(fd_, &file_stat) < 0) {
            close(fd_);
            Error::send_errno("open file failed");
        }
        file_size_ = file_stat.st_size;

        void* ret;
        if ((ret = mmap(0, file_size_, PROT_READ, MAP_SHARED, fd_, 0)) == MAP_FAILED) {
            close(fd_);
            Error::send_errno("mmap file failed");
        }

        data_ = reinterpret_cast<std::byte*>(ret);
        std::copy(data_, data_ + sizeof(elf_header_), as_bytes<Elf64_Ehdr>(elf_header_));

        parse_section_headers();
        build_section_name_to_shdr_map();
    }

    ELF::~ELF() {
        munmap(data_, file_size_);
        close(fd_);
    }

    std::optional<const Elf64_Shdr*> ELF::get_section_shdr_by_name(std::string_view name) const {
        if (section_name_to_shdr_map_.find(name) == section_name_to_shdr_map_.end()) {
            return std::nullopt;
        }
        return section_name_to_shdr_map_.at(name);
    }

    const Elf64_Shdr* ELF::get_section_shdr_by_file_addr(FileAddr addr) const {
        if (this != addr.elf()) {
            return nullptr;
        }

        for (auto& section : section_headers_) {
            if (section.sh_addr <= addr.addr() 
             && addr.addr() < section.sh_addr + section.sh_size
            ) {
                return &section;
            }
        }
        return nullptr;
    }

    const Elf64_Shdr* ELF::get_section_shdr_by_virt_addr(VirtualAddr addr) const {
        for (auto& section : section_headers_) {
            if (load_bias_ + section.sh_addr <= addr
             && addr < load_bias_ + section.sh_addr + section.sh_size
            ) {
                return &section;
            }
        }
        return nullptr;
    }

    Span<const std::byte> ELF::get_section_contents_by_name(std::string_view name) const {
        std::optional<const Elf64_Shdr*> section = get_section_shdr_by_name(name);
        if (section) {
            return {
                data_ + section.value()->sh_offset,
                section.value()->sh_size
            };
        }
        return {nullptr, std::size_t(0)};
    }

    void ELF::parse_section_headers() {
        auto n_headers = elf_header_.e_shnum;
        if (n_headers == 0 and elf_header_.e_shentsize != 0) {
            n_headers = from_bytes_as<Elf64_Shdr>(data_ + elf_header_.e_shoff).sh_size;
        }

        section_headers_.resize(elf_header_.e_shnum);
        std::copy(
            data_ + elf_header_.e_shoff,
            data_ + elf_header_.e_shoff + elf_header_.e_shnum * sizeof(Elf64_Shdr),
            reinterpret_cast<std::byte*>(section_headers_.data())
        );
    }
    

    std::string_view ELF::get_section_name_from_shstrtab(std::size_t index) const {
        const Elf64_Shdr& str_section_of_section_name = section_headers_[elf_header_.e_shstrndx];
        return { 
            reinterpret_cast<char*>(data_) 
            + str_section_of_section_name.sh_offset 
            + index 
        };
    }

    void ELF::build_section_name_to_shdr_map() {
        for (auto& section : section_headers_) {
            section_name_to_shdr_map_[get_section_name_from_shstrtab(section.sh_name)] = &section;
        }
    }

    std::string_view ELF::get_general_str_from_strtab(std::size_t index) const {
        // Although most ELF files have a general string table, 
        // in some cases they may allocate different string tables to different sections.
        // The more robust way to handle string tables is to read 
        // the sh_link field of the section header to which the string table index belongs, 
        // which provides the section index of the string table for that section. 
        // This implementation is assuming there’s a general string table for simplicity.

        std::optional<const Elf64_Shdr*> strtab_section = get_section_shdr_by_name(".strtab");
        if (!strtab_section) {
            strtab_section = get_section_shdr_by_name(".dynstr");
        }

        if (!strtab_section) {
            return "";
        }

        return {
            reinterpret_cast<char*>(data_) + strtab_section.value()->sh_offset + index
        };
    }
}