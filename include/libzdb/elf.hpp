#ifndef LIBZDB_ELF_HPP
#define LIBZDB_ELF_HPP

#include <filesystem>
#include <elf.h>
#include <vector>
#include <unordered_map>
#include <optional>
#include <libzdb/types.hpp>
#include <cassert>
/*
            +———————————————————+
            |    ELF header     |
            +———————————————————+
            |  Program headers  |
 +----------+———————————————————+---------+
 |_section _|                   | segment1|
            |       Data        |---------+
            |                   |
            |———————————————————|
            |   Section headers |
            +———————————————————+
*/
namespace zdb {

// Considering three different kinds of addresses: 
// 1. Absolute offsets from the start of the object file (corresponding to the `zdb::FileOffset` type),
// 2. Virtual addresses specified in the ELF file (corresponding to the `zdb::FileAddr` type), 
// 3. Actual virtual addresses in the executing program (corresponding to the `zdb::VirtAddr` type).

class FileOffset {
    public:
        FileOffset() = default;
        FileOffset(const ELF& elf, std::uint64_t offset): elf_(&elf), offset_(offset) {}
        std::uint64_t off() const {
            return offset_;
        }
        const ELF* elf_file() const {
            return elf_;
        }

    private:
        const ELF* elf_ = nullptr;
        std::uint64_t offset_ = 0;
};

class FileAddr {
    public:
        FileAddr() = default;
        FileAddr(const ELF& elf, std::uint64_t addr) : elf_(&elf), addr_(addr) {}

        std::uint64_t addr() const { return addr_; }
        const ELF* elf() const { return elf_; }

        VirtualAddr to_virt_addr() const;

        FileAddr operator+(std::int64_t offset) const {
            return FileAddr(*elf_, addr_ + offset);
        }

        FileAddr operator-(std::int64_t offset) const {
            return FileAddr(*elf_, addr_ - offset);
        }

        FileAddr& operator+=(std::int64_t offset) {
            addr_ += offset;
            return *this;
        }

        FileAddr& operator-=(std::int64_t offset) {
            addr_ -= offset;
            return *this;
        }

        bool operator==(const FileAddr& other) const {
            return addr_ == other.addr_ and elf_ == other.elf_;
        }

        bool operator!=(const FileAddr& other) const {
            return addr_ != other.addr_ or elf_ != other.elf_;
        }

        bool operator<(const FileAddr& other) const {
            assert(elf_ == other.elf_);
            return addr_ < other.addr_;
        }

        bool operator<=(const FileAddr& other) const {
            assert(elf_ == other.elf_);
            return addr_ <= other.addr_;
        }

        bool operator>(const FileAddr& other) const {
            assert(elf_ == other.elf_);
            return addr_ > other.addr_;
        }

        bool operator>=(const FileAddr& other) const {
            assert(elf_ == other.elf_);
            return addr_ >= other.addr_;
        }

    private:
        const ELF* elf_ = nullptr;
        std::uint64_t addr_;
};

class ELF {
    public:
        ELF(const std::filesystem::path &path);
        ~ELF();

        ELF(const ELF&) = delete;
        ELF& operator=(const ELF&) = delete; 

        std::filesystem::path path() const { return path_; }
        const Elf64_Ehdr& get_elf_header() { return elf_header_; };
        VirtualAddr load_bias() const { return load_bias_;}
        void set_load_bias(VirtualAddr addr) { load_bias_ = addr; };

        const std::vector<Elf64_Shdr>& get_section_headers() { return section_headers_; }

        std::optional<const Elf64_Shdr*> get_section_shdr_by_name(std::string_view name) const;
        const Elf64_Shdr* get_section_shdr_by_file_addr(FileAddr addr) const;
        const Elf64_Shdr* get_section_shdr_by_virt_addr(VirtualAddr addr) const;
        Span<const std::byte> get_section_contents_by_name(std::string_view name) const;

        void parse_section_headers();
        std::string_view get_section_name_from_shstrtab(std::size_t index) const;
        void build_section_name_to_shdr_map();
        std::string_view get_general_str_from_strtab(std::size_t index) const;

    private:
        int fd_;
        std::filesystem::path path_;
        std::size_t file_size_;
        std::byte *data_;
        VirtualAddr load_bias_;
        Elf64_Ehdr elf_header_;
        std::vector<Elf64_Shdr> section_headers_;
        std::unordered_map<std::string_view, Elf64_Shdr*> section_name_to_shdr_map_;
    };
}
    

#endif // LIBZDB_ELF_HPP