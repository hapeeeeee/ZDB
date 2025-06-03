#include <libzdb/elf.hpp>
#include <fcntl.h>
#include <sys/stat.h>
#include <libzdb/error.hpp>
#include <unistd.h>
#include <sys/mman.h>
#include <libzdb/bit.hpp>
#include <cxxabi.h>
#include <iostream>
namespace zdb {
ELF::ELF(const std::filesystem::path &path): path_(path) {
    if ((fd_ = open(path.c_str(), O_RDONLY)) < 0) {
        Error::send_errno("open file failed");
    }

    struct stat stats;
    if (fstat(fd_, &stats) < 0) {
        Error::send_errno("Could not retrieve ELF file stats");
    }
    file_size_ = stats.st_size;

    void* ret;
    if ((ret = mmap(0, file_size_, PROT_READ, MAP_SHARED, fd_, 0)) == MAP_FAILED) {
        close(fd_);
        Error::send_errno("mmap file failed");
    }

    data_ = reinterpret_cast<std::byte*>(ret);
    std::copy(data_, data_ + sizeof(elf_header_), as_bytes<Elf64_Ehdr>(elf_header_));

    parse_section_headers();
    build_section_name_to_shdr_map();

    parse_symbol_table();
    build_symbol_name_to_sym_map();

    dwarf_ = std::make_unique<Dwarf>(*this);
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

std::optional<FileAddr> ELF::get_section_start_file_addr_by_name(std::string_view name) const {
    std::optional<const Elf64_Shdr*> section = get_section_shdr_by_name(name);
    if (section) {
        return FileAddr{*this, section.value()->sh_offset};
    }
    return std::nullopt;
}

std::vector<const Elf64_Sym*> ELF::get_symbols_by_name(std::string_view name) const {
    auto [begin, end] = symbol_name_to_sym_.equal_range(name);
    std::vector<const Elf64_Sym*> symbols;
    for (auto it = begin; it != end; ++it) {
        symbols.push_back(it->second);
    }
    return symbols;
}

std::optional<const Elf64_Sym*> ELF::get_symbol_at_file_addr(FileAddr addr) const {
    if (addr.elf() != this) { 
        return std::nullopt; 
    }

    FileAddr null_addr;
    auto it = symbol_range_to_sym_.find(
        std::make_pair(addr, null_addr)
    );
    if (it == symbol_range_to_sym_.end()) {
        return std::nullopt;
    }
    return it->second;
}   

std::optional<const Elf64_Sym*> ELF::get_symbol_at_virt_addr(VirtualAddr addr) const {
    return get_symbol_at_file_addr(addr.to_file_addr(*this));
}

std::optional<const Elf64_Sym*> ELF::get_symbol_containing_file_addr(FileAddr addr) const {
    if (addr.elf() != this || symbol_range_to_sym_.empty()) {
        return std::nullopt;
    }

    FileAddr null_addr;
    auto it = symbol_range_to_sym_.lower_bound(
        std::make_pair(addr, null_addr)
    );

    if (it != symbol_range_to_sym_.end()) {
        auto [range, sym] = *it;
        if (range.first == addr) {
            return sym;
        }
    }

    if (it == symbol_range_to_sym_.begin()) {
        return std::nullopt;
    }

    --it;
    auto [key, value] = *it;
    if (key.first < addr && addr < key.second) {
        return value;
    }

    return std::nullopt;
}

    
std::optional<const Elf64_Sym*> ELF::get_symbol_containing_virt_addr(VirtualAddr addr) const {
    return get_symbol_containing_file_addr(addr.to_file_addr(*this));
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

void ELF::parse_symbol_table() {
    // An ELF file may have two symbol tables: 
    // a complete symbol table named `.symtab` with `SHT_SYMTAB` as the section header’s `sh_type` member,
    // and an abbreviated symbol table, which contains only the set of symbols needed for dynamic linking, 
    // named `.dynsym` with `SHT_DYNSYM` as the section type. 
    // Each ELF file may have at most one of each, and might not have a symbol table at all.
    std::optional<const Elf64_Shdr*> opt_symtab = get_section_shdr_by_name(".symtab");
    if (!opt_symtab) {
        opt_symtab = get_section_shdr_by_name(".dynsym");
        if (!opt_symtab) return;
    }

    const Elf64_Shdr* symtab_section = opt_symtab.value();
    symbol_table_.resize(symtab_section->sh_size / symtab_section->sh_entsize);
    std::copy(
        data_ + symtab_section->sh_offset,
        data_ + symtab_section->sh_offset + symtab_section->sh_size,
        reinterpret_cast<std::byte*>(symbol_table_.data())
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

void ELF::build_symbol_name_to_sym_map() {
    for (Elf64_Sym& symbol : symbol_table_) {
        std::string_view mangled_name = get_general_str_from_strtab(symbol.st_name);
        int demangle_status;
        char* demangled_name = abi::__cxa_demangle(
            mangled_name.data(), 
            nullptr, 
            nullptr, 
            &demangle_status
        );

        if (demangle_status == 0) {
            symbol_name_to_sym_.insert({demangled_name, &symbol});
            free(demangled_name);
        } 
        symbol_name_to_sym_.insert({mangled_name, &symbol});

        // If the symbol has an address and a name (meaning the st_value and st_name fields are not 0), 
        // and doesn’t point to thread-local storage (indicated by ELF64_ST_TYPE(st_info) being STT_TLS), 
        // Add an entry to the address map that maps the symbol’s address range to a pointer to the symbol.
        if (
            symbol.st_value != 0 
            && symbol.st_name != 0 
            && ELF64_ST_TYPE(symbol.st_info) != STT_TLS
        ) {
            auto range = std::make_pair(
                FileAddr{*this, symbol.st_value},
                FileAddr{*this, symbol.st_value + symbol.st_size}
            );
            symbol_range_to_sym_.insert({range, &symbol});
        }
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

namespace zdb {
const ELF* ELFCollection::get_elf_containing_address(VirtualAddr address) const {
    for (auto& elf : elves_) {
        if (auto section = elf->get_section_shdr_by_virt_addr(address); section) {
            return elf.get();
        }
    }
    return nullptr;
}

const ELF* ELFCollection::get_elf_by_path(std::filesystem::path path) const {
    for (auto& elf : elves_) {
        if (elf->path() == path) {
            return elf.get();
        }
    }
    return nullptr;
}

const ELF* ELFCollection::get_elf_by_filename(std::string_view name) const {
    for (auto& elf : elves_) {
        if (elf->path().filename() == name) {
            return elf.get();
        }
    }
    return nullptr;
}
}