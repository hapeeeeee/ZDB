#ifndef LIBZDB_ELF_HPP
#define LIBZDB_ELF_HPP

#include <filesystem>
#include <elf.h>
#include <vector>
#include <unordered_map>
#include <optional>
#include <libzdb/types.hpp>

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
class ELF {
    public:
        ELF(const std::filesystem::path &path);
        ~ELF();

        ELF(const ELF&) = delete;
        ELF& operator=(const ELF&) = delete; 

        std::filesystem::path path() const { return path_; }
        const Elf64_Ehdr& get_elf_header() { return elf_header_; };
        const std::vector<Elf64_Shdr>& get_section_headers() { return section_headers_; }

        std::optional<const Elf64_Shdr*> get_section_shdr_by_name(std::string_view name) const;
        Span<const std::byte> get_section_content_contents(std::string_view name) const;

        void parse_section_headers();
        std::string_view get_section_name(std::size_t index) const;
        void build_section_name_to_shdr_map();

    private:
        int fd_;
        std::filesystem::path path_;
        std::size_t file_size_;
        std::byte *data_;
        Elf64_Ehdr elf_header_;
        std::vector<Elf64_Shdr> section_headers_;
        std::unordered_map<std::string_view, Elf64_Shdr*> section_name_to_shdr_map_;
    };
}
    

#endif // LIBZDB_ELF_HPP