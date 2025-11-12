#include <libzdb/types.hpp>
#include <libzdb/elf.hpp>
#include <cassert>

zdb::VirtualAddr zdb::FileAddr::to_virt_addr() const {
    assert(elf_ && "to_VirtualAddr called on null address");
    auto section = elf_->get_section_shdr_by_file_addr(*this);
    if (!section) return VirtualAddr{};
    return VirtualAddr { addr_ + elf_->load_bias().addr() };
}

zdb::FileAddr zdb::VirtualAddr::to_file_addr(const ELF& elf) const {
    auto section = elf.get_section_shdr_by_virt_addr(*this);
    if (!section) return FileAddr{};
    return FileAddr{ elf, addr_ - elf.load_bias().addr()};
}

zdb::FileAddr zdb::VirtualAddr::to_file_addr(const ELFCollection& elves) const {
    const zdb::ELF * elf = elves.get_elf_containing_address(*this);
    if (!elf) return FileAddr{};
    return to_file_addr(*elf);
}