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
    }

    ELF::~ELF() {
        munmap(data_, file_size_);
        close(fd_);
    }

    std::optional<const Elf64_Shdr*> ELF::get_section_shdr_by_name(std::string_view name) const {
        
    }

    Span<const std::byte> ELF::get_section_content_contents(std::string_view name) const {

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
    

    std::string_view ELF::get_section_name(std::size_t index) const {
        const Elf64_Shdr& str_section_of_section_name = section_headers_[elf_header_.e_shstrndx];
        return { 
            reinterpret_cast<char*>(data_) 
            + str_section_of_section_name.sh_offset 
            + index 
        };
    }

    void ELF::build_section_name_to_shdr_map() {
        for (auto& section : section_headers_) {
            section_name_to_shdr_map_[get_section_name(section.sh_name)] = &section;
        }
    }
}