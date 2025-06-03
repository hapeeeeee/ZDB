#ifndef LIBZDB_ELF_HPP
#define LIBZDB_ELF_HPP

#include <filesystem>
#include <elf.h>
#include <vector>
#include <unordered_map>
#include <optional>
#include <libzdb/types.hpp>
#include <cassert>
#include <map>
#include <libzdb/dwarf.hpp>
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
    VirtualAddr load_bias() const { return load_bias_;}
    void notify_loaded(VirtualAddr addr) { load_bias_ = addr; };
    Dwarf& get_dwarf() { return *dwarf_; }
    const Dwarf& get_dwarf() const { return *dwarf_; }

    const std::vector<Elf64_Shdr>& get_section_headers() { return section_headers_; }

    std::optional<const Elf64_Shdr*> get_section_shdr_by_name(std::string_view name) const;
    const Elf64_Shdr* get_section_shdr_by_file_addr(FileAddr addr) const;
    const Elf64_Shdr* get_section_shdr_by_virt_addr(VirtualAddr addr) const;
    Span<const std::byte> get_section_contents_by_name(std::string_view name) const;
    std::optional<FileAddr> get_section_start_file_addr_by_name(std::string_view name) const;

    std::vector<const Elf64_Sym*> get_symbols_by_name(std::string_view name) const;
    std::optional<const Elf64_Sym*> get_symbol_at_file_addr(FileAddr addr) const;
    std::optional<const Elf64_Sym*> get_symbol_at_virt_addr(VirtualAddr addr) const;
    std::optional<const Elf64_Sym*> get_symbol_containing_file_addr(FileAddr addr) const;
    std::optional<const Elf64_Sym*> get_symbol_containing_virt_addr(VirtualAddr addr) const;

    void parse_section_headers();
    void parse_symbol_table();

    void build_section_name_to_shdr_map();
    void build_symbol_name_to_sym_map();

    std::string_view get_section_name_from_shstrtab(std::size_t index) const;
    std::string_view get_general_str_from_strtab(std::size_t index) const;

    FileOffset data_pointer_as_file_offset(const std::byte* ptr) const {
        return FileOffset(*this, ptr - data_);
    }
    const std::byte* file_offset_as_data_pointer(FileOffset offset) const {
        return data_ + offset.off();
    }

  private:
    int fd_;
    std::filesystem::path path_;
    std::size_t file_size_;
    std::byte *data_;
    VirtualAddr load_bias_;
    std::unique_ptr<Dwarf> dwarf_;
    
    Elf64_Ehdr elf_header_;
    std::vector<Elf64_Shdr> section_headers_;
    std::unordered_map<std::string_view, Elf64_Shdr*> section_name_to_shdr_map_;

    std::vector<Elf64_Sym> symbol_table_;
    std::unordered_multimap<std::string_view, Elf64_Sym*> symbol_name_to_sym_;
    struct range_comparator {
        bool operator() (
            std::pair<FileAddr, FileAddr> lhs,
            std::pair<FileAddr, FileAddr> rhs
        ) const {
            return lhs.first < rhs.first;
        }
    };
    std::map<std::pair<FileAddr, FileAddr>, Elf64_Sym*, range_comparator> symbol_range_to_sym_;

};

class ELFCollection {
  public:
    void push(std::unique_ptr<ELF> elf) {
        elves_.push_back(std::move(elf));
    }

    template <class F>
    void for_each(F f) {
        for (auto& elf : elves_) {
            f(*elf);
        }
    }
    template <class F>
    void for_each(F f) const {
        for (const auto& elf : elves_) {
            f(*elf);
        }
    }

    const ELF* get_elf_containing_address(VirtualAddr address) const;
    const ELF* get_elf_by_path(std::filesystem::path path) const;
    const ELF* get_elf_by_filename(std::string_view name) const;

  private:
    std::vector<std::unique_ptr<ELF>> elves_;

};
}
    


#endif // LIBZDB_ELF_HPP