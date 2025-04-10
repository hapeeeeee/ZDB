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

// For Attr 
namespace zdb {
    FileAddr Attr::as_address() const {
        Cursor cur({ location_, cu_->data().end() });
        if (form_ != DW_FORM_addr) Error::send("Invalid address type");
        auto elf = cu_->dwarf_info()->elf();
        return FileAddr{ *elf, cur.u64() };

    }

    std::uint32_t Attr::as_section_offset() const {
        Cursor cur({ location_, cu_->data().end() });
        if (form_ != DW_FORM_sec_offset) Error::send("Invalid offset type");
        return cur.u32();
    }

    Span<const std::byte> Attr::as_block() const {
        std::size_t size;
        Cursor cur({ location_, cu_->data().end() });

        switch (form_) {
        case DW_FORM_block1:
            size = cur.u8();
            break;
        case DW_FORM_block2:
            size = cur.u16();
            break;
        case DW_FORM_block4:
            size = cur.u32();
            break;
        case DW_FORM_block:
            size = cur.uleb128();
            break;
        default:
            Error::send("Invalid block type");
        }
        return { cur.position(), size };
    }

    std::uint64_t Attr::as_int() const {
        Cursor cur({ location_, cu_->data().end() });
        switch (form_) {
        case DW_FORM_data1:
            return cur.u8();
        case DW_FORM_data2:
            return cur.u16();
        case DW_FORM_data4:
            return cur.u32();
        case DW_FORM_data8:
            return cur.u64();
        case DW_FORM_udata:
            return cur.uleb128();
        default:
            Error::send("Invalid integer type");
        }
    }

    std::string_view Attr::as_string() const {
        Cursor cur({ location_, cu_->data().end() });
        switch (form_) {
        case DW_FORM_string:
            return cur.string(); 
        case DW_FORM_strp: {
            auto offset = cur.u32();
            auto stab = cu_
                ->dwarf_info()
                ->elf()
                ->get_section_contents_by_name(".debug_str");
            Cursor stab_cur({ stab.begin() + offset, stab.end() });
            return stab_cur.string(); 
        }
        default:
            Error::send("Invalid string type");
        }
    }

    DIE Attr::as_reference() const {
        Cursor cur({ location_, cu_->data().end() });
        std::size_t offset;
        switch (form_) {
        case DW_FORM_ref1:
            offset = cur.u8(); break;
        case DW_FORM_ref2:
            offset = cur.u16(); break;
        case DW_FORM_ref4:
            offset = cur.u32(); break;
        case DW_FORM_ref8:
            offset = cur.u64(); break;
        case DW_FORM_ref_udata:
            offset = cur.uleb128(); break;
        case DW_FORM_ref_addr: {
            // `DW_FORM_ref_addr` form can reference data in other compile units, 
            // so its offset is relative to the start of the `.debug_info` section. 
            offset = cur.u32();
            Span<const std::byte> section = cu_
                ->dwarf_info()
                ->elf()
                ->get_section_contents_by_name(".debug_info");
            auto die_pos = section.begin() + offset;

            auto& cus = cu_->dwarf_info()->compile_units();
            auto cu_finder = [=](auto& cu) {
                return cu->data().begin() <= die_pos and cu->data().end() > die_pos;
            };
            auto cu_for_die_pos = std::find_if(
                begin(cus), 
                end(cus), 
                cu_finder
            );
            Cursor ref_cur({ die_pos, cu_for_die_pos->get()->data().end() });
            return parse_die(**cu_for_die_pos, ref_cur);
        }
        default:
            Error::send("Invalid reference type");
        }

        Cursor ref_cur({ cu_->data().begin() + offset, cu_->data().end() });
        return parse_die(*cu_, ref_cur);
    }

    RangeList Attr::as_range_list() const {
        auto section = cu_
            ->dwarf_info()
            ->elf()
            ->get_section_contents_by_name(".debug_ranges");
        auto offset = as_section_offset();
        Span<const std::byte> data(section.begin() + offset, section.end());
        auto root = cu_->root();
        FileAddr base_address = root.contains(DW_AT_low_pc) ?
            root[DW_AT_low_pc].as_address() :
            FileAddr {};
        return { cu_, data, base_address };
    }
}

// For DIE::ChangeRange
namespace zdb {
    DIE::ChildrenRange::iterator::iterator(const zdb::DIE& d) {
        Cursor next_cur({ d.next_, d.cu_->data().end() });
        op_die_ = parse_die(*d.cu_, next_cur);
    }

    bool DIE::ChildrenRange::iterator::operator==(const iterator& rhs) const {
        auto lhs_null = !op_die_.has_value() || !op_die_->abbrev_entry();
        auto rhs_null = !rhs.op_die_.has_value() || !rhs.op_die_->abbrev_entry();
        if (lhs_null && rhs_null) return true;
        if (lhs_null || rhs_null) return false;
        return op_die_->abbrev_ == rhs.op_die_->abbrev_ && op_die_->next() == rhs.op_die_->next();
    }

    DIE::ChildrenRange::iterator& DIE::ChildrenRange::iterator::operator++() {
        if (!op_die_.has_value() || !op_die_->abbrev_entry()) return *this;

        if (!op_die_->abbrev_entry()->has_children) {
            Cursor next_cur({ op_die_->next_, op_die_->cu_->data().end() });
            op_die_ = parse_die(*op_die_->cu_, next_cur);
        } else if (op_die_->contains(DW_AT_sibling)) {
            op_die_ = op_die_.value()[DW_AT_sibling].as_reference();
        } else {
            iterator sub_children(*op_die_);
            while (sub_children->abbrev_) ++sub_children;
            Cursor next_cur({ sub_children->next_, op_die_->cu_->data().end() });
            op_die_ = parse_die(*op_die_->cu_, next_cur);
        }
        return *this;
    }

    DIE::ChildrenRange::iterator DIE::ChildrenRange::iterator::operator++(int) {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

    DIE::ChildrenRange DIE::children() const {
        return ChildrenRange(*this);
    }
}

// For DIE
namespace zdb {
    bool DIE::contains(std::uint64_t attribute) const {
        auto& specs = abbrev_->attr_specs;
        return std::find_if(
                specs.begin(), 
                specs.end(),
                [=](auto spec) { 
                    return spec.attr == attribute; 
                }
            ) != end(specs);
    }

    Attr DIE::operator[](std::uint64_t attribute) const {
        auto& specs = abbrev_->attr_specs;
        for (std::size_t i = 0; i < specs.size(); ++i) {
            if (specs[i].attr == attribute) {
                return { cu_, specs[i].attr, specs[i].form, attr_locs_[i] };
            }
        }
        Error::send("Attribute not found");
    }

    FileAddr DIE::low_pc() const {
        if (contains(DW_AT_ranges)) {
            auto first_entry = (*this)[DW_AT_ranges].as_range_list().begin();
            return first_entry->low;
        } else if (contains(DW_AT_low_pc)) {
            return (*this)[DW_AT_low_pc].as_address();
        }
        Error::send("DIE does not have low PC");
    }

    FileAddr DIE::high_pc() const {
        if (contains(DW_AT_ranges)) {
            auto ranges = (*this)[DW_AT_ranges].as_range_list();
            auto it = ranges.begin();
            while (std::next(it) != ranges.end()) ++it;
            return it->high;
        }
        else if (contains(DW_AT_high_pc)) {
            auto attr = (*this)[DW_AT_high_pc];
            FileAddr addr;
            if (attr.form() == DW_FORM_addr) {
                return attr.as_address();
            } else {
                return low_pc() + attr.as_int();
            }
        }
        Error::send("DIE does not have high PC");
    }

    bool DIE::contains_file_address(FileAddr address) const {
        if (address.elf() != this->cu_->dwarf_info()->elf()) {
            return false;
        }

        if (contains(DW_AT_ranges)) {
            return (*this)[DW_AT_ranges].as_range_list().contains(address);
        } else if (contains(DW_AT_low_pc)) {
            return low_pc() <= address && high_pc() > address;
        }

        return false;
    }
}

// For RangeList
namespace zdb {
    RangeList::iterator::iterator(
        const CompileUnit* cu, 
        Span<const std::byte> data, 
        FileAddr base_address
    ) : cu_(cu), data_(data), base_address_(base_address), pos_(data.begin()) 
    {
        ++(*this);
    }

    zdb::RangeList::iterator& zdb::RangeList::iterator::operator++() {
        auto elf = cu_->dwarf_info()->elf();
        constexpr auto base_address_flag = ~static_cast<std::uint64_t>(0);
        Cursor cur({ pos_, data_.end() });
        while (true) {
            current_.low = FileAddr { *elf, cur.u64() };
            current_.high = FileAddr { *elf, cur.u64() };
            if (current_.low.addr() == base_address_flag) {
                // `base address selectors`, so sets the base address
                base_address_ = current_.high;
            } else if (current_.low.addr() == 0 and current_.high.addr() == 0) {
                // `end-of-list indicator`
                pos_ = nullptr;
                break;
            } else {
                // `Regular entries selectors`
                pos_ = cur.position();
                current_.low += base_address_.addr();
                current_.high += base_address_.addr();
                break;
            }
        }
        return *this;
    }

    zdb::RangeList::iterator zdb::RangeList::iterator::operator++(int) {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

    RangeList::iterator RangeList::begin() const {
        return { cu_, data_, base_address_ };
    }

    RangeList::iterator RangeList::end() const {
        return {};
    }

    bool RangeList::contains(FileAddr address) const {
        return std::any_of(
            begin(), 
            end(),
            [=](auto& e) { return e.contains(address); }
        );
    }
}

// For Dwarf&CompileUnit
namespace zdb {
    Dwarf::Dwarf(const ELF &parent) : elf_(&parent) {
        compile_units_ = parse_compile_units(*this, parent);
    }

    const std::unordered_map<std::uint64_t, Abbrev> &Dwarf::get_abbrev_table(std::size_t offset) {
        if (!abbrev_tables_.count(offset)) {
            abbrev_tables_.insert({offset, parse_abbrev_table(*elf_, offset)});
        }
        return abbrev_tables_.at(offset);
    }

    const std::unordered_map<std::uint64_t, Abbrev>& CompileUnit::abbrev_table() const {
        return parent_->get_abbrev_table(abbrev_offset_);
    }

    const CompileUnit* Dwarf::compile_unit_containing_address(FileAddr address) const {
        for (auto& cu : compile_units_) {
            if (cu->root().contains_file_address(address)) {
                return cu.get();
            }
        }
        return nullptr;
    }

    std::optional<DIE> Dwarf::function_containing_address(FileAddr address) const {
        index();
        for (auto& [name, entry] : function_index_) {
            Cursor cur({ entry.pos, entry.cu->data().end() });
            auto d = parse_die(*entry.cu, cur);
            if (d.contains_file_address(address) && d.abbrev_entry()->tag == DW_TAG_subprogram) {
                // `DW_TAG_subprogram` is a regular function
                return d;
            }
        }
        return std::nullopt;
    }

    std::vector<DIE> Dwarf::find_functions(std::string name) const {
        index();
        std::vector<DIE> found;
        auto [begin, end] = function_index_.equal_range(name);
        std::transform(
            begin, 
            end, 
            std::back_inserter(found), 
            [](auto& pair) {
                auto [name, entry] = pair;
                cursor cur({ entry.pos, entry.cu->data().end() });
                return parse_die(*entry.cu, cur);
            }
        );
        return found;
    }

    void Dwarf::index() const {
        if (!function_index_.empty()) {
            return;
        }
        for (auto& cu : compile_units_) {
            index_die(cu->root());
        }
    }

    void Dwarf::index_die(const DIE& current) const {
        
    }

    DIE CompileUnit::root() const {
        std::size_t header_size = 4 /*size*/ + 2 /*version*/ + 4 /*abbrev offset*/ + 1 /*address size*/;
        Cursor cursor({ data_.begin() + header_size, data_.end() });
        return parse_die(*this, cursor);
    }
}
