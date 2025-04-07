#include <libzdb/dwarf.hpp>
#include <libzdb/elf.hpp>
#include <libzdb/error.hpp>

namespace {
    // `.debug_info` section is split into information for each compile unit involved in the compilation of the program.
    // Every compile unit begins with a compile unit header, 
    // which describes four important characteristics of that unit:
    //    A 4-byte unsigned integer representing the byte size of the information 
    //      for this compile unit (excluding this field itself, but including the rest of the header)
    // 
    //    A 2-byte unsigned integer representing the DWARF version 
    //      for this compile unit information (four, in our case)
    // 
    //    A 4-byte unsigned integer representing the offset into the `.debug_abbrev`
    //      section at which the abbreviation table for this compile unit begins;
    // 
    //    A 1-byte unsigned integer representing the byte size of an address
    //      on the system (8 for x64)
    std::unique_ptr<zdb::CompileUnit> parse_compile_unit(zdb::Dwarf& dwarf, const zdb::ELF& elf, Cursor &cursor) {
        const std::byte* pos = cursor.position();
        auto size = cursor.u32();
        auto version = cursor.u16();
        auto abbrev_offset = cursor.u32();
        auto address_size = cursor.u8();

        if (size == 0xffffffff) {
            zdb::Error::send("Only DWARF32 is supported");
        }

        if (version != 4) {
            zdb::Error::send("Only DWARF version 4 is supported");
        }

        if (address_size != 8) {
            zdb::Error::send("Invalid address size for DWARF");
        }

        // add the size of a std::uint32_t to the compile unit size, because the
        // reported size in the compile unit header doesn’t include the size field itself
        size += sizeof(std::uint32_t);
        zdb::Span<const std::byte> data{pos, size};
        return std::make_unique<zdb::CompileUnit>(dwarf, data, abbrev_offset);
    }

    std::vector<std::unique_ptr<zdb::CompileUnit>> 
    parse_compile_units(zdb::Dwarf& dwarf, const zdb::ELF& elf) {
        auto debug_info = elf.get_section_contents_by_name(".debug_info");
        Cursor cursor(debug_info);
        
        std::vector<std::unique_ptr<zdb::CompileUnit>> units;
        while (!cursor.is_finished()) {
            auto unit = parse_compile_unit(dwarf, elf, cursor);
            cursor += unit->data().size();
            units.push_back(std::move(unit));
        }
        return units;
    }

    zdb::DIE parse_die(const zdb::CompileUnit& cu, Cursor& cursor) {
        auto pos = cursor.position();
        auto abbrev_code = cursor.uleb128();
        if (abbrev_code == 0) {
            auto next = cursor.position();
            return zdb::DIE{ next };
        }

        auto& abbrev_table = cu.abbrev_table();
        const zdb::Abbrev& abbrev_entry = abbrev_table.at(abbrev_code);

        std::vector<const std::byte*> attr_locs;
        attr_locs.reserve(abbrev_entry.attr_specs.size());
        for (auto& attr : abbrev_entry.attr_specs) {
            attr_locs.push_back(cursor.position());
            cursor.skip_form(attr.form);
        }
        auto next = cursor.position();
        return zdb::DIE(pos, &cu, &abbrev_entry, std::move(attr_locs), next);
    }
    
    // Each Abbreviation entry structure:
    //  ULEB128 : `abbreviation code` to reference the table, if 0, end of table
    //  ULEB128 : `tag` for `DW_TAG_*`, found in `detail/dwarf.h`
    //  bool    : whether the DIE has child DIEs
    //  (ULEB128, ULEB128)* : list of attribute specifications, ends with (0, 0)
    std::unordered_map<std::uint64_t, zdb::Abbrev> parse_abbrev_table(const zdb::ELF &elf, std::size_t offset) {
        auto span_abbrev = elf.get_section_contents_by_name(".debug_abbrev");
        Cursor cursor(span_abbrev);
        cursor += offset;

        std::unordered_map<std::uint64_t, zdb::Abbrev> abbrev_table;
        std::uint64_t code = 0;
        do {
            // Parse one entry
            code = cursor.uleb128();
            auto tag = cursor.uleb128();
            auto children = static_cast<bool>(cursor.u8());

            std::vector<zdb::AttrSpec> attr_specs;
            std::uint64_t attr = 0;
            do {
                attr = cursor.uleb128();
                auto form = cursor.uleb128();
                if (attr) {
                    attr_specs.push_back(zdb::AttrSpec{attr, form});
                }
            } while (attr);

            if (code) {
                abbrev_table.emplace(
                    code,
                    zdb::Abbrev{code, tag, children, std::move(attr_specs)}
                );
            }
        } while (code);

        return abbrev_table;
    }
}

namespace zdb {
    DIE::ChildrenRange::iterator::iterator(const zdb::DIE& d) {
        Cursor next_cur({ d.next_, d.cu_->data().end() });
        op_die_ = parse_die(*d.cu_, next_cur);
    }
}

bool zdb::DIE::ChildrenRange::iterator::operator==(const iterator& rhs) const {
    auto lhs_null = !op_die_.has_value() || !op_die_->abbrev_entry();
    auto rhs_null = !rhs.op_die_.has_value() || !rhs.op_die_->abbrev_entry();
    if (lhs_null && rhs_null) return true;
    if (lhs_null || rhs_null) return false;
    return op_die_->abbrev_ == rhs.op_die_->abbrev_ && op_die_->next() == rhs.op_die_->next();
}

zdb::DIE::ChildrenRange::iterator&
zdb::DIE::ChildrenRange::iterator::operator++() {
    if (!op_die_.has_value() || !op_die_->abbrev_entry()) return *this;
    if (!op_die_->abbrev_entry()->has_children) {
        Cursor next_cur({ op_die_->next_, op_die_->cu_->data().end() });
        op_die_ = parse_die(*op_die_->cu_, next_cur);
    } else {
        iterator sub_children(*die_);
        while (sub_children->abbrev_) ++sub_children;
        Cursor next_cur({ sub_children->next_, die_->cu_->data().end() });
        op_die_ = parse_die(*die_->cu_, next_cur);
    }
    return *this;
}

zdb::DIE::ChildrenRange::iterator
zdb::DIE::ChildrenRange::iterator::operator++(int) {
    auto tmp = *this;
    ++(*this);
    return tmp;
}

namespace zdb {
    Dwarf::Dwarf(const ELF &parent) : elf_(&parent) {
        compile_units_ = parse_compile_units(*this, parent);
    }

    const std::unordered_map<std::uint64_t, Abbrev> &Dwarf::get_abbrev_table(std::size_t offset) {
        if (!abbrev_tables_.count(offset)) {
        }
            abbrev_tables_.insert({offset, parse_abbrev_table(*elf_, offset)});
        return abbrev_tables_.at(offset);
    }

    const std::unordered_map<std::uint64_t, Abbrev>& CompileUnit::abbrev_table() const {
        return parent_->get_abbrev_table(abbrev_offset_);
    }

    DIE CompileUnit::root() const {
        std::size_t header_size = 4 /*size*/ + 2 /*version*/ + 4 /*abbrev offset*/ + 1 /*address size*/;
        Cursor cursor({ data_.begin() + header_size, data_.end() });
        return parse_die(*this, cursor);
    }
}
