#include <libzdb/dwarf.hpp>
#include <libzdb/types.hpp>
#include <libzdb/bit.hpp>
#include <string_view>
#include <algorithm>
#include <libzdb/elf.hpp>
#include <libzdb/error.hpp>
#include <iostream>
#include <variant>
#include <libzdb/process.hpp>

namespace {
    zdb::VirtualAddr read_frame_base_result(
        const zdb::DwarfExpression::result& loc,
        const zdb::Registers& regs
    ) {
        const zdb::DwarfExpression::simple_location *simple_loc = 
            std::get_if<zdb::DwarfExpression::simple_location>(&loc);
        if (!simple_loc) zdb::Error::send("Unsupported frame base location");
        if (auto addr_res = std::get_if<zdb::DwarfExpression::address_result>(simple_loc)) {
            return addr_res->address;
        }
        zdb::Error::send("Unsupported frame base location");
    }

    std::size_t eh_frame_pointer_encoding_size(std::uint8_t encoding) {
        switch (encoding & 0x7) {
            case DW_EH_PE_absptr: return 8;
            case DW_EH_PE_udata2: return 2;
            case DW_EH_PE_udata4: return 4;
            case DW_EH_PE_udata8: return 8;
            default: zdb::Error::send("Invalid pointer encoding");
        }
    }
    std::uint64_t parse_eh_frame_pointer_with_base(
        Cursor& cur, 
        std::uint8_t encoding, 
        std::uint64_t base
    ) {
        switch (encoding & 0x0f) {
        case DW_EH_PE_absptr: return base + cur.u64();
        case DW_EH_PE_uleb128: return base + cur.uleb128();
        case DW_EH_PE_udata2: return base + cur.u16();
        case DW_EH_PE_udata4: return base + cur.u32();
        case DW_EH_PE_udata8: return base + cur.u64();
        case DW_EH_PE_sleb128: return base + cur.sleb128();
        case DW_EH_PE_sdata2: return base + cur.s16();
        case DW_EH_PE_sdata4: return base + cur.s32();
        case DW_EH_PE_sdata8: return base + cur.s64();
        default: zdb::Error::send("Unknown eh_frame pointer encoding");
        }
    }

    std::uint64_t parse_eh_frame_pointer(
        const zdb::ELF& elf,
        Cursor& cur, 
        std::uint8_t encoding,
        std::uint64_t pc, 
        std::uint64_t text_section_start,
        std::uint64_t data_section_start, 
        std::uint64_t func_start
    ) {
        std::uint64_t base = 0;
        // We mask out the most significant bit (0x80) because it corresponds to the 
        // indirect encoding scheme, which we don’t need to handle
        switch (encoding & 0x70) {
        case DW_EH_PE_absptr: break;
        case DW_EH_PE_pcrel:
            base = pc; break;
        case DW_EH_PE_textrel:
            base = text_section_start; break;
        case DW_EH_PE_datarel:
            base = data_section_start; break;
        case DW_EH_PE_funcrel:
            base = func_start; break;
        default: zdb::Error::send("Unknown eh_frame pointer encoding");
        }

        return parse_eh_frame_pointer_with_base(cur, encoding, base);
    }

    // The .eh_frame_hdr section contains a binary search table that maps addresses
    // to offsets of the FDEs that store the corresponding unwind information.
    // The section consists of seven fields:
    //  - version (std::uint8_t) The version of the .eh_frame_hdr format (mustbe 1).
    //  - eh_frame_ptr_enc (std::uint8_t) The encoding format of the eh_frame_ptr field.
    //  - fde_count_enc (std::uint8_t) The encoding format of the fde_count field.
    //  - table_enc (std::uint_8_t) The encoding format of the entries in the binary search table. 
    //      This will always be a fixed-size encoding (that is, not ULEB128) because otherwise 
    //      jumping to arbitrary entries would not be possible.
    //  - eh_frame_ptr (encoded pointer) A pointer to the start of the .eh_frame section.
    //  - fde_count (encoded integer) The number of entries in the binary search table. This will 
    //      always be an absolute encoding. 
    //  - binary_search_table (array of integers encoded according to the table_enc field) A table 
    //      containing the number of entries given by the fde_count field. Each entry of the table 
    //      corresponds to a single FDE and consists of two encoded integers: the value of the 
    //      initial_location field for the FDE and the offset of the FDE from the start of the object
    //      file. The entries are sorted in an ascending order by the initial_location value.
    zdb::CallFrameInformation::eh_hdr parse_eh_hdr(zdb::Dwarf& dwarf) {
        auto elf = dwarf.elf();
        auto eh_hdr_start = *elf->get_section_start_file_addr_by_name(".eh_frame_hdr");
        auto text_section_start = *elf->get_section_start_file_addr_by_name(".text");
        auto eh_hdr_data = elf->get_section_contents_by_name(".eh_frame_hdr");
        Cursor cur(eh_hdr_data);
        auto start = cur.position();
        auto version = cur.u8();
        auto eh_frame_ptr_enc = cur.u8();
        auto fde_count_enc = cur.u8();
        auto table_enc = cur.u8();

        // We don’t really need this value, as we can easily retrieve the pointer from sdb::elf, so
        // we throw away the encoded pointer
        (void)parse_eh_frame_pointer_with_base(cur, eh_frame_ptr_enc, 0);
        
        uint64_t fde_count = parse_eh_frame_pointer_with_base(cur, fde_count_enc, 0);
        auto search_table = cur.position();
        return { start, search_table, fde_count, table_enc, nullptr };
    }

    // In the EH format, CIEs consist of 10 fields:
    //  - length (std::uint32_t) The byte size of this CIE, not including the length field itself.
    //  - CIE_id (std::uint32_t) Distinguishes CIEs from FDEs. The DWARF standard specifies this field 
    //      to be 0xffffffff for CIEs, but the EH format specifies it to be 0.
    //  - version (std::uint8_t) The version of the call frame information that this CIE is representing. 
    //      For formats based on DWARF 2, this is 1, for formats based on DWARF 3, it is 3, and for formats 
    //      based on DWARF 4, it is 4.
    //  - augmentation_string (null-terminated string) ABI-specific augmentations. I’ll detail the options 
    //      that the EH format specifies momentarily. augmentation_string field may have the following specifiers:
    //      - z Indicates that there is a ULEB128 specifying the size of the augmentation data (not including 
    //          the ULEB128 itself). If there is augmentation data, this must be the first entry in it.
    //      - L Indicates that there is a byte specifying the encoding of a pointer to additional information 
    //          for exception handling routines called the language-specific data area (LSDA). We won’t use 
    //          this pointer in our debugger.
    //      - R Indicates that there is a byte specifying the encoding of FDE code pointers for linked FDEs.
    //      - P Indicates that there is a byte specifying the encoding of a pointer, followed by the encoded 
    //          pointer itself, which indicates a personality function used to handle language-specific tasks 
    //          by exception handling routines. We won’t use this pointer in our debugger.
    //  - address_size (std::uint8_t) The byte size of an address on the target machine. On x64, this is 8. 
    //      This field is present only in CIEs based on DWARF 4 and up.
    //  - segment_size (std::uint8_t) The byte size of segment selectors on the target machine. On x64, 
    //      this is 0. This field is present only in CIEs based on DWARF 4 and up.
    //  - code_alignment_factor (ULEB128) Tunes the behavior of certain CFI instructions.
    //  - data_alignment_factor (SLEB128) Tunes the behavior of certain CFI instructions.
    //  - return_address_register (std::uint8_t in DWARF 2, ULEB128 otherwise) The DWARF register number 
    //      for the register that stores the return address. On x64, this will be register 16, which is a 
    //      made-up register number specifically for return addresses, but which we’ve assigned to rip so
    //      that restoring rip is like returning from a function. 
    //  - augmentation_data (array of std::uint8_t values) Stores data that is outlined in the 
    //      augmentation_string field. This field is present only in the EH format, not in DWARF.
    //  - initial_instructions (array of std::uint8_t values) A sequence of CFI instructions that specify 
    //      how to unwind the stack and are prepended to all FDEs linked to this CIE.
    zdb::CallFrameInformation::common_information_entry parse_cie(Cursor cur) {
        const std::byte * start = cur.position();
        uint32_t length = cur.u32() + 4;
        uint32_t id = cur.u32();
        uint8_t version = cur.u8();
        if (!(version == 1 || version == 3 || version == 4)) {
            zdb::Error::send("Invalid CIE version");
        }

        std::string_view augmentation = cur.string();
        if (!augmentation.empty() && augmentation[0] != 'z') {
            zdb::Error::send("Invalid CIE augmentation");
        }

        if (version == 4) {
            auto address_size = cur.u8();
            auto segment_size = cur.u8();
            if (address_size != 8)
                zdb::Error::send("Invalid address size");
            if (segment_size != 0)
                zdb::Error::send("Invalid segment size");
        }

        auto code_alignment_factor = cur.uleb128();
        auto data_alignment_factor = cur.sleb128();
        auto return_address_register = 
            version == 1 ? cur.u8() : cur.uleb128();
        
        // By default, an FDE code pointer’s encoding uses an absolute 64-bit address.
        std::uint8_t fde_pointer_encoding = DW_EH_PE_udata8 | DW_EH_PE_absptr;
        for (char c : augmentation) {
            switch (c) {
            case 'z': {
                cur.uleb128();
                break;
            }
            case 'R': {
                fde_pointer_encoding = cur.u8(); 
                break;
            }
            case 'L': {
                cur.u8(); 
                break;
            }
            case 'P': {
                auto encoding = cur.u8();
                (void)parse_eh_frame_pointer_with_base(cur, encoding, 0);
                break;
            }
            default: zdb::Error::send("Invalid CIE augmentation");
            }
        }

        zdb::Span<const std::byte> instructions = { cur.position(), start + length };
        bool fde_has_augmentation = !augmentation.empty();
        return { 
            length, 
            code_alignment_factor,
            data_alignment_factor, 
            fde_has_augmentation,
            fde_pointer_encoding, 
            instructions 
        };

    }

    // FDEs consist of only 6 fields:
    //  - length (std::uint32_t) The byte size of this FDE, not including the length field itself.
    //  - CIE_id (std::int32_t) The negative distance from the current parse position to the linked 
    //      CIE. For example, a value of 40 means that the CIE starts at 40 bytes before the current 
    //      parse position.
    //  - initial_location (encoded pointer) A pointer to the first instruction to which this FDE 
    //      applies. The encoding for this pointer is given by the R augmentation of the linked CIE 
    //      and defaults to 64-bit absolute values if there is no R augmentation.
    //  - address_range (encoded integer) The byte size of the code to which this FDE applies. The 
    //      encoding for this pointer is given by the R augmentation of the linked CIE and defaults 
    //      to 64-bit absolute values if there is no R augmentation. However, this value should 
    //      always be interpreted as an absolute integer value, even if the R augmentation says it 
    //      should be relative to some base address.
    //  - augmentation_data (array of std::uint8_t) Stores data that is outlined in the linked CIE’s 
    //      augmentation_string field. This field is present only in the EH format, not DWARF.
    //  - instructions (array of std::uint8_t) A sequence of call frame information instructions that 
    //      specify how to unwind the stack
    zdb::CallFrameInformation::frame_description_entry 
    parse_fde(const zdb::CallFrameInformation& cfi, Cursor cur) {
        auto start = cur.position();
        auto length = cur.u32() + 4;
        auto elf = cfi.dwarf().elf();
        auto current_offset = elf->data_pointer_as_file_offset(cur.position());
        zdb::FileOffset cie_offset { *elf, current_offset.off() - cur.s32() /* CIE_id */ };
        auto& cie = cfi.get_cie(cie_offset);

        current_offset = elf->data_pointer_as_file_offset(cur.position());
        zdb::FileAddr text_section_start = elf
            ->get_section_start_file_addr_by_name(".text")
            .value_or(zdb::FileAddr{});
        auto initial_location_addr = parse_eh_frame_pointer(
            *elf,
            cur,
            cie.fde_pointer_encoding, 
            current_offset.off(),
            text_section_start.addr(), 
            0, 
            0
        );
        zdb::FileAddr initial_location{ *elf, initial_location_addr };
        // While also encoded according to the R augmentation in the linked CIE, 
        // only the low 4 bits are used for address_range, so we can call 
        // `parse_eh_frame_pointer_with_base` rather than `parse_eh_frame_pointer` 
        // to handle it.
        auto address_range = parse_eh_frame_pointer_with_base(
            cur, 
            cie.fde_pointer_encoding, 
            0
        );

        if (cie.fde_has_augmentation) {
            auto augmentation_length = cur.uleb128();
            cur += augmentation_length;
        }

        zdb::Span<const std::byte> instructions = { cur.position(), start + length };
        return { length, &cie, initial_location, address_range, instructions };
    }

    std::unique_ptr<zdb::CallFrameInformation> parse_call_frame_information(zdb::Dwarf& dwarf) {
        auto eh_hdr = parse_eh_hdr(dwarf);
        return std::make_unique<zdb::CallFrameInformation>(&dwarf, eh_hdr);
    }

    // 12. file_names (a sequence of file entries) The source files involved in this compilation. 
    //      Each entry contains the following: 
    //        - a null-terminated string representing the filename, either as an absolute path, 
    //              a path relative to the compilation directory, or a path relative to one of the directories 
    //              specified in the include_directories field; 
    //        - a ULEB128 representing the directory to which this path is relative, if it is a relative path 
    //              (a value of 0 indicates that the compilation directory contains the path, 
    //              while a value greater than 0 represents an index into the include_directories field,
    //              which numbers its entries starting at 1); 
    //        - a ULEB128 representing the file’s last modification time;
    //        - a ULEB128 representing the byte size of the file. A single null byte terminates the sequence 
    //              of entries.
    zdb::LineTable::file parse_line_table_file(
        Cursor& cur,
        std::filesystem::path compilation_dir,
        const std::vector<std::filesystem::path>& include_directories
    ) {
        auto file = cur.string();
        auto dir_index = cur.uleb128();
        auto modification_time = cur.uleb128();
        auto file_length = cur.uleb128();
        std::filesystem::path path = file;
        if (file[0] != '/') {
            if (dir_index == 0) {
                path = compilation_dir / std::string(file);
            } else {
                path = include_directories[dir_index - 1] / std::string(file);
            }
        }
        return {path.string(), modification_time, file_length};
    }

    // The line table program header consists of 12 fields:
    //  1. unit_length (uint32_t): The byte size of the line number information 
    //      for this compile unit, not including the unit_length field itself.
    //  2. version (uint16_t) The version of the line number information. 
    //      For DWARF 4, this value is 4.
    //  3. header_length (uint32_t): The number of bytes from the end of the header_length
    //      field until the beginning of the line number program.
    //  4. minimum_instruction_length (uint8_t): The byte size of the smallest machine instruction. 
    //      On x64, this is 1. 
    //  5. maximum_operations_per_instruction (uint8_t) The maximum number of operations that may be encoded 
    //      in an instruction. For architectures that are not very long instruction word (VLIW) architectures, 
    //      this will always be 1 in x64. 
    //  6. default_is_stmt (uint8_t) Whether rows in the matrix should be interpreted as the beginning of 
    //      source code statements by default. This allows the producer to save space if most machine 
    //      instructions are ordered in the same way as the source code statements, which is usually
    //      true for unoptimized code.
    //  7. line_base (int8_t) The minimum value that special opcodes can add to the line register. 
    //      You’ll learn about special opcodes soon.
    //  8. line_range (uint8_t) The range of values special opcodes can add to the line register.
    //  9. opcode_base (uint8_t) The number assigned to the first special opcode.
    // 10. standard_opcode_lengths (an array of uint8_t values) The number of operands that each 
    //      standard opcode takes. The first element of this array corresponds to the first standard opcode, 
    //      the second element to the second opcode, and so on. This field allows producers to describe any
    //      additional standard opcodes they’ve used to consumers.
    // 11. include_directories (a sequence of null-terminated strings) Contains each path that was searched 
    //      for included files. Each entry is either an absolute path or a path relative to the compilation 
    //      directory (specified with the `DW_AT_comp_dir` attribute on the root compile unit DIE). The
    //      sequence ends with a single null byte.
    // 12. file_names (a sequence of file entries) The source files involved in this compilation. 
    //      see more detail in `parse_line_table_file` comment.
    std::unique_ptr<zdb::LineTable> parse_line_table(const zdb::CompileUnit& cu) {
        auto section = cu
            .dwarf_info()
            ->elf()
            ->get_section_contents_by_name(".debug_line");

        if (!cu.root().contains(DW_AT_stmt_list)) return nullptr;
        auto offset = cu.root()[DW_AT_stmt_list].as_section_offset();
        Cursor cur({ section.begin() + offset, section.end() });

        auto size = cur.u32();
        auto end = cur.position() + size;
        auto version = cur.u16();
        if (version != 4) 
            zdb::Error::send("Only DWARF 4 is supported");

        (void)cur.u32(); // Header length
        auto minimum_instruction_length = cur.u8();
        if (minimum_instruction_length != 1)
            zdb::Error::send("Invalid minimum instruction length");

        auto maximum_operations_per_instruction = cur.u8();
        if (maximum_operations_per_instruction != 1)
            zdb::Error::send("Invalid maximum operations per instruction");
        
        auto default_is_stmt = cur.u8();
        auto line_base = cur.s8();
        auto line_range = cur.u8();
        auto opcode_base = cur.u8();

        // We won’t support DWARF extensions, but we will support producers that decide 
        // to not use all of the standard opcodes. Each standard opcode is assigned a 
        // number, beginning at 1 and incrementing. DWARF 4 has 12 standard opcodes.
        std::array<std::uint8_t, 12> expected_opcode_lengths {
            0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1
        };
        for (auto i = 0; i < opcode_base - 1; ++i) {
            if (cur.u8() != expected_opcode_lengths[i]) {
                zdb::Error::send("Unexpected opcode length");
            }   
        }

        std::vector<std::filesystem::path> include_directories;
        std::filesystem::path compilation_dir (cu.root()[DW_AT_comp_dir].as_string());
        for (auto dir = cur.string(); !dir.empty(); dir = cur.string()) {
            if (dir[0] == '/') {
                include_directories.push_back(std::string(dir));
            } else { 
                include_directories.push_back(compilation_dir / std::string(dir));
            }
        }

        std::vector<zdb::LineTable::file> file_names;
        while (*cur.position() != std::byte(0)) {
            file_names.push_back(parse_line_table_file(cur, compilation_dir, include_directories));
        }
        // parse line_header completed.
        cur += 1; // bringing the cursor to the beginning of the line table program. 

        zdb::Span<const std::byte> data { cur.position(), end };
        return std::make_unique<zdb::LineTable>(
            data, 
            &cu,
            default_is_stmt,
            line_base, 
            line_range,
            opcode_base,
            std::move(include_directories), 
            std::move(file_names) 
        );
    }


    // `.debug_info` section is split into information for each compile unit involved in the compilation of the program.
    // Every compile unit begins with a compile unit header, 
    // which describes four important characteristics of that unit:
    //    A 4-byte unsigned integer representing the byte size of the information 
    //      for this compile unit (excluding this field itself, but including the rest of the header)
    // 
    //    A 2-byte unsigned integer representing the DWARF version 
    //      for this compile unit information (four, in our case)
    // 
    //    A 4-byte unsigned integer representing the offset into the `.debug_abbcrev`
    //      section at which the abbreviation table for this compile unit begins;
    // 
    //    A 1-byte unsigned integer representing the byte size of an address
    //      on the system (8 for x64)
    std::unique_ptr<zdb::CompileUnit> parse_compile_unit(zdb::Dwarf& dwarf, const zdb::ELF& elf, Cursor cursor) {
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

    bool path_ends_with(
        const std::filesystem::path& lhs,
        const std::filesystem::path& rhs
    ) {
        auto lhs_size = std::distance(lhs.begin(), lhs.end());
        auto rhs_size = std::distance(rhs.begin(), rhs.end());
        if (rhs_size > lhs_size) {
            return false;
        }
        auto start = std::next(lhs.begin(), lhs_size - rhs_size);
        return std::equal(start, lhs.end(), rhs.begin());
    }
}

// For stack unwinding rules
// The rule for restoring a register can be one of the following:
//  - undefined: It’s not possible to restore the register value.
//  - register(R): The previous value of the register is stored in another register, with the DWARF register number R.
//  - same_value: The register hasn’t been modified from its previous value. (This is a special case of register(R) 
//      where R is the same as the register for which the rule is defined.)
//  - offset(N) The previous value of the register is saved at an offset of N from the current CFA.
//  - val_offset(N) The previous value of the register is the current CFA plus N.
//  - expression(E) The previous value of the register is located at the address produced by executing the DWARF 
//      expression E.
//  - val_expression(E): The previous value of the register is the value produced by executing the DWARF expression E.
// 
// In addition to register rules, we must handle the following rules for
// computing the CFA:
//  - register_and_offset(R,N): The CFA is calculated by taking the address stored in the register with the DWARF 
//      register number R and adding the offset N to it.
//  - expression(E): The CFA is calculated by executing the DWARF expression E
namespace {
    struct undefined_rule {};
    struct register_rule {
        std::uint32_t reg;
    };
    struct same_rule {};
    struct offset_rule {
        std::int64_t offset;
    };
    struct val_offset_rule {
        std::int64_t offset;
    };
    struct expr_rule {
        // 接受一个ULEB128操作数和一个附加DW_FORM_block操作数，
        // 前者表示要为其定义规则的DWARF寄存器编号，后者表示DWARF表达式E，
        // 并将寄存器的规则设置为表达式（E）。在执行E之前，此表达式将CFA推入DWARF表达式堆栈。
        // 结果是寄存器的值的地址
        zdb::DwarfExpression expr;
    };
    struct val_expr_rule {
        // 同expr_rule, 结果为寄存器的值
        zdb::DwarfExpression expr;
    };
    struct cfa_register_rule {
        // cfa的回溯是通过寄存器的值+偏移
        std::uint32_t reg;
        std::int64_t offset;
    };
    struct cfa_expr_rule {
        // cfa的回溯是通过Dwarf表达式
        zdb::DwarfExpression expr;
    };



    struct unwind_context {
        Cursor cur{ {nullptr, nullptr} };
        zdb::FileAddr location;
        using rule = std::variant<
            undefined_rule, 
            register_rule,
            same_rule, 
            offset_rule,
            val_offset_rule,
            expr_rule,
            val_expr_rule
        >;
        // DWARF register id to register restore rules
        using ruleset = std::unordered_map<std::uint32_t, rule>;
        ruleset cie_register_rules;
        ruleset register_rules;

        using cfa_rule_type = std::variant<cfa_register_rule, cfa_expr_rule>;
        cfa_rule_type cfa_rule;

        std::vector<std::pair<ruleset, cfa_rule_type>> rule_stack;
    };

    void execute_cfi_instruction(
        const zdb::ELF& elf,
        const zdb::CallFrameInformation::frame_description_entry& fde,
        unwind_context& ctx, 
        zdb::FileAddr pc
    ) {
        auto& cie = *fde.cie;
        auto& cur = ctx.cur;
        auto text_section_start = *elf.get_section_start_file_addr_by_name(".text");
        auto plt_start = elf
            .get_section_start_file_addr_by_name(".got.plt")
            .value_or(zdb::FileAddr{});

        // Call frame information instructions require one or more bytes to encode. 
        // The most significant 2 bits of the first byte encode the primary opcode. 
        // The other 6 bits can store either an extended opcode or operands for the instruction.
        auto opcode = cur.u8();
        auto primary_opcode = opcode & 0xc0;
        auto extended_opcode = opcode & 0x3f;
        if (primary_opcode) {
            switch (primary_opcode) {
            case DW_CFA_advance_loc:
                ctx.location += extended_opcode * cie.code_alignment_factor;
                break;
            case DW_CFA_offset: { 
                // takes two operands: a DWARF register number encoded in the least significant 
                // 6 bits of the opcode and an additional ULEB128 offset. 
                std::int64_t offset = static_cast<std::int64_t>(cur.uleb128()) * cie.data_alignment_factor;
                ctx.register_rules.emplace(extended_opcode, offset_rule{ offset });
                break;
            }
            case DW_CFA_restore:
                // resets the rule for the given register to its original value in the CIE’s register rules
                // Note that GCC’s unwinder treats DW_CFA_restore in the same way as DW_CFA_same_value,
                // but we’re going to follow the spec and the behavior of libunwind
                ctx.register_rules.emplace(
                    extended_opcode, 
                    ctx.cie_register_rules.at(extended_opcode)
                );
                break;
            }
        }
        else if (extended_opcode) {
            switch (extended_opcode) {
                case DW_CFA_set_loc: {
                    zdb::FileOffset current_offset = elf.data_pointer_as_file_offset(cur.position());
                    auto loc = parse_eh_frame_pointer(
                        elf, 
                        cur, 
                        cie.fde_pointer_encoding,
                        current_offset.off(),
                        text_section_start.addr(),
                        plt_start.addr(), 
                        fde.initial_location.addr()
                    );
                    ctx.location = zdb::FileAddr{ elf, loc };
                    break;
                }
                case DW_CFA_advance_loc1:
                    ctx.location += cur.u8() * cie.code_alignment_factor;
                    break;
                case DW_CFA_advance_loc2:
                    ctx.location += cur.u16() * cie.code_alignment_factor;
                    break;
                case DW_CFA_advance_loc4:
                    ctx.location += cur.u32() * cie.code_alignment_factor;
                    break;
                case DW_CFA_def_cfa:
                    ctx.cfa_rule = cfa_register_rule {
                        static_cast<std::uint32_t>(cur.uleb128()),
                        static_cast<std::uint32_t>(cur.uleb128())
                    };
                    break;
                case DW_CFA_def_cfa_sf:
                    ctx.cfa_rule = cfa_register_rule {
                        static_cast<std::uint32_t>(cur.uleb128()),
                        cur.sleb128() * cie.data_alignment_factor
                    };
                    break;
                case DW_CFA_def_cfa_register:
                    std::get<cfa_register_rule>(ctx.cfa_rule).reg = cur.uleb128();
                    break;
                case DW_CFA_def_cfa_offset:
                    std::get<cfa_register_rule>(ctx.cfa_rule).offset = cur.uleb128();
                    break;
                case DW_CFA_def_cfa_offset_sf:
                    std::get<cfa_register_rule>(ctx.cfa_rule).offset = cur.sleb128() * cie.data_alignment_factor;
                    break;
                case DW_CFA_def_cfa_expression: {
                    uint64_t length = cur.uleb128();
                    auto expr = zdb::DwarfExpression{
                        elf, 
                        { cur.position(), cur.position() + length }, 
                        true 
                    };
                    ctx.cfa_rule = cfa_expr_rule{ expr };
                    break;
                }
                case DW_CFA_undefined:
                    ctx.register_rules.emplace(cur.uleb128(), undefined_rule{});
                    break;
                case DW_CFA_same_value: {
                    ctx.register_rules.emplace(cur.uleb128(), same_rule{});
                    break;
                }
                case DW_CFA_offset_extended: {
                    auto reg = cur.uleb128();
                    auto offset = static_cast<std::int64_t>(cur.uleb128()) * cie.data_alignment_factor;
                    ctx.register_rules.emplace(reg, offset_rule{ offset });
                    break;
                }
                case DW_CFA_offset_extended_sf: {
                    auto reg = cur.uleb128();
                    auto offset = cur.sleb128() * cie.data_alignment_factor;
                    ctx.register_rules.emplace(reg, offset_rule{ offset });
                    break;
                }
                case DW_CFA_val_offset: {
                    auto reg = cur.uleb128();
                    auto offset = static_cast<std::int64_t>(cur.uleb128()) * cie.data_alignment_factor;
                    ctx.register_rules.emplace(reg, val_offset_rule{ offset });
                    break;
                }
                case DW_CFA_val_offset_sf: {
                    auto reg = cur.uleb128();
                    auto offset = cur.sleb128() * cie.data_alignment_factor;
                    ctx.register_rules.emplace(reg, val_offset_rule{ offset });
                    break;
                }
                case DW_CFA_register: {
                    auto reg = cur.uleb128();
                    ctx.register_rules.emplace(
                        reg,
                        register_rule{ static_cast<std::uint32_t>(cur.uleb128()) }
                    );
                    break;
                }
                case DW_CFA_expression: {
                    uint64_t reg = cur.uleb128();
                    uint64_t length = cur.uleb128();
                    auto expr = zdb::DwarfExpression{
                        elf, 
                        { cur.position(), cur.position() + length }, 
                        true 
                    };
                    ctx.register_rules.emplace(reg, expr_rule{ expr });
                    break;
                }
                case DW_CFA_val_expression: {
                    uint64_t reg = cur.uleb128();
                    uint64_t length = cur.uleb128();
                    auto expr = zdb::DwarfExpression{
                        elf, 
                        { cur.position(), cur.position() + length }, 
                        true 
                    };
                    ctx.register_rules.emplace(reg, val_expr_rule{ expr });
                    break;
                }
                case DW_CFA_restore_extended: {
                    auto reg = cur.uleb128();
                    ctx.register_rules.emplace(reg, ctx.cie_register_rules.at(reg));
                    break;
                }
                case DW_CFA_remember_state: {
                    ctx.rule_stack.push_back({ ctx.register_rules, ctx.cfa_rule });
                    break;
                }
                case DW_CFA_restore_state: {
                    ctx.register_rules = ctx.rule_stack.back().first;
                    ctx.cfa_rule = ctx.rule_stack.back().second;
                    ctx.rule_stack.pop_back();
                    break;
                }
            }
        }
    }

    zdb::Registers execute_unwind_rules(
        unwind_context& ctx, 
        zdb::Registers& old_regs,
        const zdb::Process& proc
    ) {
        auto dwexp_addr_result = [&](const auto& res) {
            auto& loc = std::get<zdb::DwarfExpression::simple_location>(res);
            auto& addr_res = std::get<zdb::DwarfExpression::address_result>(loc);
            return zdb::VirtualAddr{ addr_res.address.addr() };
        };

        zdb::Registers unwound_regs = old_regs;

        std::uint64_t cfa;
        if (auto reg_rule = std::get_if<cfa_register_rule>(&ctx.cfa_rule)) {
            zdb::RegisterInfo reg_info = zdb::find_register_info_by_dwarf_id(reg_rule->reg);
            cfa = std::get<std::uint64_t>(old_regs.read(reg_info)) + reg_rule->offset;
        }
        else if (auto expr = std::get_if<cfa_expr_rule>(&ctx.cfa_rule)) {
            zdb::DwarfExpression::result res = expr->expr.eval(proc, old_regs);
            cfa = dwexp_addr_result(res).addr();
        }

        old_regs.set_cfa(zdb::VirtualAddr{ cfa });
        unwound_regs.write_by_id(zdb::RegisterId::rsp, { cfa }, false);
        for (auto [reg, rule] : ctx.register_rules) {
            zdb::RegisterInfo reg_info = zdb::find_register_info_by_dwarf_id(reg);
            if (auto undef = std::get_if<undefined_rule>(&rule)) {
                unwound_regs.undefine(reg_info.id);
            } 
            else if (auto same = std::get_if<same_rule>(&rule)) {
                // Do nothing.
            }
            else if (auto reg = std::get_if<register_rule>(&rule)) {
                zdb::RegisterInfo other_reg = zdb::find_register_info_by_dwarf_id(reg->reg);
                unwound_regs.write(reg_info, old_regs.read(other_reg), false);
            }
            else if (auto offset = std::get_if<offset_rule>(&rule)) {
                zdb::VirtualAddr addr = zdb::VirtualAddr{ cfa + offset->offset };
                std::uint64_t value = zdb::from_bytes_as<std::uint64_t>(
                    proc.read_memory(addr, 8 /* 8 in x64 */).data()
                );
                unwound_regs.write(reg_info, { value }, false);
            }
            else if (auto val_offset = std::get_if<val_offset_rule>(&rule)) {
                auto addr = cfa + val_offset->offset;
                unwound_regs.write(reg_info, { addr }, false);
            } 
            else if (auto expr = std::get_if<expr_rule>(&rule)) {
                auto res = expr->expr.eval(proc, old_regs, true);
                auto addr = dwexp_addr_result(res);
                uint64_t value = proc.read_memory_as<std::uint64_t>(addr);
                unwound_regs.write(reg_info, { value }, false);
            } 
            else if (auto val_expr = std::get_if<val_expr_rule>(&rule)) {
                auto res = val_expr->expr.eval(proc, old_regs, true);
                auto addr = dwexp_addr_result(res);
                unwound_regs.write(reg_info, { addr.addr() }, false);
            } 
        }
        return unwound_regs;
    }
}

// For CallFrameInfo
namespace zdb {
    const CallFrameInformation::common_information_entry& 
    CallFrameInformation::get_cie(FileOffset at) const {
        uint64_t offset = at.off();
        if (cie_map_.count(offset)) {
            return cie_map_.at(offset);
        }

        Span<const std::byte> section = at.elf()->get_section_contents_by_name(".eh_frame");
        Cursor cur({ at.elf()->file_offset_as_data_pointer(at), section.end()});
        auto cie = parse_cie(cur);
        cie_map_.emplace(offset, cie);
        return cie_map_.at(offset);
    }

    Registers CallFrameInformation::unwind(const Process& proc, FileAddr pc, Registers& regs) const {
        auto fde_start = eh_hdr_[pc];
        auto eh_frame_end = dwarf_->elf()->get_section_contents_by_name(".eh_frame").end();
        Cursor cur({ fde_start, eh_frame_end });
        auto fde = parse_fde(*this, cur);
        if (pc < fde.initial_location || pc >= fde.initial_location + fde.address_range) {
            zdb::Error::send("No unwind information at PC");
        }
        unwind_context ctx{};
        ctx.cur = Cursor(fde.cie->instructions);
        while (!ctx.cur.is_finished()) {
            execute_cfi_instruction(*dwarf_->elf(), fde, ctx, pc);
        }

        ctx.cie_register_rules = ctx.register_rules;
        ctx.cur = Cursor(fde.instructions);
        ctx.location = fde.initial_location;
        while (!ctx.cur.is_finished() && ctx.location <= pc) {
            execute_cfi_instruction(*dwarf_->elf(), fde, ctx, pc);
        }
        return execute_unwind_rules(ctx, regs, proc);
    }

    const std::byte* CallFrameInformation::eh_hdr::operator[](FileAddr address) const {
        auto elf = address.elf();
        auto text_section_start = *elf->get_section_start_file_addr_by_name(".text");
        auto encoding_size = eh_frame_pointer_encoding_size(encoding);
        auto row_size = encoding_size * 2;

        std::size_t low = 0;
        std::size_t high = count - 1;
        while (low <= high) {
            std::size_t mid = (low + high) / 2;
            Cursor cur({ search_table + mid * row_size, search_table + count * row_size });
            auto current_offset = elf->data_pointer_as_file_offset(cur.position());
            auto eh_hdr_offset = elf->data_pointer_as_file_offset(start);
            auto entry_address = parse_eh_frame_pointer(
                *elf, 
                cur, 
                encoding, 
                current_offset.off(),
                text_section_start.addr(), 
                eh_hdr_offset.off(), 
                0
            );
            if (entry_address < address.addr()) {
                low = mid + 1;
            }
            else if (entry_address > address.addr()) {
                if (mid == 0) {
                    Error::send("Address not found in eh_hdr");
                }
                high = mid - 1;
            }
            else {
                high = mid;
                break;
            }
        }

        Cursor cur({ search_table + high * row_size + encoding_size, search_table + count * row_size });
        auto current_offset = elf->data_pointer_as_file_offset(cur.position());
        auto eh_hdr_offset = elf->data_pointer_as_file_offset(start);
        auto fde_offset_int = parse_eh_frame_pointer(
            *elf, 
            cur, 
            encoding, 
            current_offset.off(),
            text_section_start.addr(), 
            eh_hdr_offset.off(), 
            0
        );

        FileOffset fde_offset{ *elf, fde_offset_int };
        return elf->file_offset_as_data_pointer(fde_offset);
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

    DwarfExpression Attr::as_expression(bool in_frame_info) const {
        Cursor cursor({ location_, cu_->data().end() });
        auto length = cursor.uleb128();
        Span<const std::byte> data{ cursor.position(), length };
        return DwarfExpression{ *cu_->dwarf_info(), data, in_frame_info };
    }

    LocationList Attr::as_location_list(bool in_frame_info) const {
        zdb::Span<const std::byte> section = cu_
            ->dwarf_info()
            ->elf()
            ->get_section_contents_by_name(".debug_loc");
        Cursor cursor({ location_, cu_->data().end() });
        auto offset = cursor.u32();
        Span<const std::byte> data(section.begin() + offset, section.end());
        return LocationList{ *cu_->dwarf_info(), *cu_, data, in_frame_info };
    }

    DwarfExpression::result Attr::as_evaluated_location(
        const Process& proc,
        const Registers& regs,
        bool in_frame_info
    ) const {
        if (form_ == DW_FORM_exprloc) {
            auto expr = as_expression(in_frame_info);
            return expr.eval(proc, regs);
        }
        else if (form_ == DW_FORM_sec_offset) {
            auto loc_list = as_location_list(in_frame_info);
            return loc_list.eval(proc, regs);
        }
        else {
            Error::send("Invalid location type");
        }
    }
}

// For LineTable
namespace zdb {
    LineTable::iterator::iterator(const LineTable* table_) 
    : table_(table_) , pos_(table_->data_.begin())
    {
        registers_.is_stmt = table_->default_is_stmt_;
        ++(*this);
    }

    LineTable::iterator LineTable::begin() const {
        return iterator(this);
    }

    LineTable::iterator LineTable::end() const {
        return {};
    }

    LineTable::iterator LineTable::get_entry_by_address(FileAddr address) const {
        auto prev = begin();
        if (prev == end()) {
            return prev;
        }

        auto it = prev;
        for (++it; it != end(); prev = it++) {
            if (prev->address <= address && address < it->address && !prev->end_sequence) {
                return prev;
            }
        }
        return end();
    }

    std::vector<LineTable::iterator> LineTable::get_entries_by_line(
        std::filesystem::path path, 
        std::size_t line
    ) const {
        std::vector<iterator> entries;
        for (auto it = begin(); it != end(); ++it) {
            auto& entry_path = it->file_entry->path;
            if (it->line == line) {
                if ((path.is_absolute() && entry_path == path) 
                    ||(path.is_relative() && path_ends_with(entry_path, path))
                ) {
                    entries.push_back(it);
                }
            }
        }
        return entries;
    }

    LineTable::iterator& LineTable::iterator::operator++() {
        if (pos_ == table_->data_.end()) {
            pos_ = nullptr;
            return *this;
        }

        bool emitted = false;
        do {
            emitted = execute_instruction();
        } while (!emitted);

        current_.file_entry = &table_->file_names_[current_.file_index - 1];
        return *this;
    }

    LineTable::iterator LineTable::iterator::operator++(int) {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

    // Each instruction belongs to one of three categories:
    //  `Standard opcode`: A uint8_t opcode that names an operation, such as
    //      `DW_LNS_advance_line`, for advancing the current line by a given amount,
    //      or DW_LNS_set_basic_block, for setting the basic_block register to true. The
    //      number and type of operands that a standard opcode takes depends on
    //      which opcode it is.
    //  `Extended opcode`: Used to encode more complex instructions. Extended opcodes 
    //      begin with a null byte, followed by a ULEB128 giving the size of the next instruction. 
    //      After this size comes a uint8_t providing the extended opcode and then the operands.
    //  `Special opcode`: Used to advance the current line and address and emit
    //      a matrix row, all in a single opcode. Special opcodes consist of a single
    //       uint8_t with no operands.
    bool LineTable::iterator::execute_instruction() {
        auto elf = table_->cu_->dwarf_info()->elf();
        Cursor cur({ pos_, table_->data_.end() });
        auto opcode = cur.u8();
        bool emitted = false;
        if (0 < opcode && opcode < table_->opcode_base_) {
            // Handle standard opcode, See more detail in `include/libzdb/detail/dwarf.h`
            switch (opcode) {
            case DW_LNS_copy: 
                current_ = registers_;
                registers_.basic_block_start = false;
                registers_.prologue_end = false;
                registers_.epilogue_begin = false;
                registers_.discriminator = 0;
                emitted = true;
                break;
            case DW_LNS_advance_pc:
                registers_.address += cur.uleb128();
                break;
            case DW_LNS_advance_line:
                registers_.line += cur.sleb128();
                break;
            case DW_LNS_set_file:
                registers_.file_index = cur.uleb128();
                break;
            case DW_LNS_set_column:
                registers_.column = cur.uleb128();
                break;
            case DW_LNS_negate_stmt:
                registers_.is_stmt = !registers_.is_stmt;
                break;
            case DW_LNS_set_basic_block:
                registers_.basic_block_start = true;
                break;
            case DW_LNS_const_add_pc:
                registers_.address += (255 - table_->opcode_base_) / table_->line_range_;
                break;
            case DW_LNS_fixed_advance_pc:
                registers_.address += cur.u16();
                break;
            case DW_LNS_set_prologue_end:
                registers_.prologue_end = true;
                break;
            case DW_LNS_set_epilogue_begin:
                registers_.epilogue_begin = true;
                break;
            case DW_LNS_set_isa:
                //  we ignore the isa register, DW_LNS_set_isa does nothing, because only x64.
                break;
            default:
                Error::send("Unexpected standard opcode");
            }
        }
        else if (opcode == 0) {
            auto length = cur.uleb128();
            auto extended_opcode = cur.u8();

            switch (extended_opcode) {
            case DW_LNE_end_sequence: 
                registers_.end_sequence = true;
                current_ = registers_;
                registers_ = entry{};
                registers_.is_stmt = table_->default_is_stmt_;
                emitted = true;
                break;
            case DW_LNE_set_address: 
                registers_.address = FileAddr(*elf, cur.u64());
                break;
            case DW_LNE_define_file: { 
                auto compilation_dir = table_->cu_->root()[DW_AT_comp_dir].as_string();
                auto file = parse_line_table_file(
                    cur, 
                    std::string(compilation_dir), 
                    table_->include_directories_
                );
                table_->file_names_.push_back(file);
                break;
            }
            case DW_LNE_set_discriminator:
                registers_.discriminator = cur.uleb128();
                break;
            default:
                Error::send("Unexpected extended opcode");
            }
        }
        else {
            // see `Special opcode` thory in page.357/389, chapter13, book:"building a debugger"
            auto adjusted_opcode = opcode - table_->opcode_base_;
            registers_.address += adjusted_opcode / table_->line_range_;
            registers_.line += table_->line_base_ + (adjusted_opcode % table_->line_range_);
            current_ = registers_;
            registers_.basic_block_start = false;
            registers_.prologue_end = false;
            registers_.epilogue_begin = false;
            registers_.discriminator = 0;
            emitted = true;
        }
        pos_ = cur.position();
        return emitted;
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

    std::optional<std::string_view> DIE::name() const {
        if (contains(DW_AT_name)) {
            return (*this)[DW_AT_name].as_string();
        }
        if (contains(DW_AT_specification)) {
            return (*this)[DW_AT_specification].as_reference().name();
        }
        if (contains(DW_AT_abstract_origin)) {
            return (*this)[DW_AT_abstract_origin].as_reference().name();
        }
        return std::nullopt;
    }

    SourceLocation DIE::location() const {
        return { &file(), line() };
    }

    const LineTable::file& DIE::file() const {
        std::uint64_t idx;
        if (abbrev_->tag == DW_TAG_inlined_subroutine) {
            idx = (*this)[DW_AT_call_file].as_int();
        }
        else {
            idx = (*this)[DW_AT_decl_file].as_int();
        }
        return this->cu_->lines().file_names()[idx - 1];
    }

    std::uint64_t DIE::line() const {
        if (abbrev_->tag == DW_TAG_inlined_subroutine) {
            return (*this)[DW_AT_call_line].as_int();
        }

        return (*this)[DW_AT_decl_line].as_int();
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

// For DwarfExpr 
namespace zdb {
    DwarfExpression::result DwarfExpression::eval(
        const Process& proc,
        const Registers& regs,
        bool push_cfa
    ) const {
        Cursor cursor({ expr_data_.begin(), expr_data_.end() });

        std::vector<std::uint64_t> stack;
        if (push_cfa) stack.push_back(regs.cfa().addr());
        std::optional<simple_location> most_recent_location;
        std::vector<pieces_result::piece> pieces;

        // 默认情况下，我们假设DWARF表达式的结果是一个地址，
        // 但是DW_OP_stack_value操作码可能会覆盖这个值
        bool result_is_address = true;

        // 堆栈操作: 算数运算
        auto binop = [&](auto op) {
            auto rhs = stack.back();
            stack.pop_back();
            auto lhs = stack.back();
            stack.pop_back();
            stack.push_back(op(lhs, rhs));
        };

         // 堆栈操作: 关系运算
        auto relop = [&](auto op) {
            auto rhs = static_cast<std::int64_t>(stack.back());
            stack.pop_back();
            auto lhs = static_cast<std::int64_t>(stack.back());
            stack.pop_back();
            stack.push_back(op(lhs, rhs) ? 1 : 0);
        };

        auto virt_pc = VirtualAddr{
            regs.read_by_id_as<std::uint64_t>(RegisterId::rip)
        };
        FileAddr file_pc = virt_pc.to_file_addr(*parent_->elf());
        std::optional<zdb::DIE> func = parent_->function_containing_address(file_pc);

        auto get_current_location = [&]() {
            simple_location loc;
            if (stack.empty()) {
                loc = most_recent_location.value_or(empty_result{});
                most_recent_location.reset();
            }
            else if (result_is_address) {
                loc = address_result{ VirtualAddr{stack.back()} };
                stack.pop_back();
            }
            else {
                loc = literal_result{ stack.back() };
                stack.pop_back();
                result_is_address = true;
            }
            return loc;
        };
    
        // 执行dwarf表达式
        while (!cursor.is_finished()) {
            uint8_t opcode = cursor.u8();

            // 直接push 0~31进入栈
            if (opcode >= DW_OP_lit0 && opcode <= DW_OP_lit31) {
                stack.push_back(opcode - DW_OP_lit0);
            }
            // 直接从寄存器0~32拿取值
            else if (opcode >= DW_OP_reg0 && opcode <= DW_OP_reg31) {
                std::int32_t reg = opcode - DW_OP_reg0;
                // 在栈上下文中,需要将寄存器值入栈
                if (in_frame_info_) {
                    Registers::Value reg_val = regs.read(find_register_info_by_dwarf_id(reg));
                    stack.push_back(std::get<std::uint64_t>(reg_val));
                }
                // 寄存器id为dwarf表达式结果
                else {
                    most_recent_location = register_result{ static_cast<std::uint64_t>(reg) };
                }
            }
            // 新的地址 = 寄存器0~32的值 + 偏移
            // DW_OP_breg0 32: 寄存器0的值 加上 32 得到新的地址
            else if (opcode >= DW_OP_breg0 && opcode <= DW_OP_breg31) {
                std::int32_t reg = opcode - DW_OP_breg0;
                Registers::Value reg_val = regs.read(find_register_info_by_dwarf_id(reg));
                int64_t offset = cursor.sleb128();
                stack.push_back(std::get<std::uint64_t>(reg_val) + offset);
            }

            switch (opcode) {
            case DW_OP_addr: {
                // DW_OP_addr 给出的是一个“文件地址”（file address）
                // 但调试器在运行时要操作的是虚拟地址空间中的内存
                auto addr = FileAddr{ *(parent_->elf()), cursor.u64() };
                stack.push_back(addr.to_virt_addr().addr());
                break;
            }
            case DW_OP_const1u:
                stack.push_back(cursor.u8());
                break;
            case DW_OP_const1s:
                stack.push_back(cursor.s8());
                break;
            case DW_OP_const2u:
                stack.push_back(cursor.u16());
                break;
            case DW_OP_const2s:
                stack.push_back(cursor.s16());
                break;
            case DW_OP_const4u:
                stack.push_back(cursor.u32());
                break;
            case DW_OP_const4s:
                stack.push_back(cursor.s32());
                break;
            case DW_OP_const8u:
                stack.push_back(cursor.u64());
                break;
            case DW_OP_const8s:
                stack.push_back(cursor.s64());
                break;
            case DW_OP_constu:
                stack.push_back(cursor.uleb128());
                break;
            case DW_OP_consts:
                stack.push_back(cursor.sleb128());
                break;
            case DW_OP_bregx: {
                // 新的地址 = 寄存器0~32的值 + 偏移
                // DW_OP_bregx 54 32: 寄存器54的值 加上 32 得到新的地址
                Registers::Value reg_val = regs.read(
                    zdb::find_register_info_by_dwarf_id(cursor.uleb128())
                );
                stack.push_back(std::get<std::uint64_t>(reg_val) + cursor.sleb128());
                break;
            }
            case DW_OP_fbreg: {
                // DW_OP_fbreg -50: 值存在于帧基数的-50字节偏移处，
                int64_t  offset = cursor.sleb128();
                auto fb_loc = func
                    .value()[DW_AT_frame_base]
                    .as_evaluated_location(proc, regs, /*in_frame_info=*/true);
                auto fb_addr = read_frame_base_result(fb_loc, regs);
                stack.push_back(fb_addr.addr() + offset);
                break;
            }
            case DW_OP_dup:
                stack.push_back(stack.back());
                break;
            case DW_OP_drop:
                stack.pop_back();
                break;
            case DW_OP_pick:
                stack.push_back(stack.rbegin()[cursor.u8()]);
                break;
            case DW_OP_over:
                stack.push_back(stack.rbegin()[1]);
                break;
            case DW_OP_swap:
                std::swap(stack.rbegin()[0], stack.rbegin()[1]);
                break;
            case DW_OP_rot:
                std::rotate(stack.rbegin(), stack.rbegin() + 1, stack.rbegin() + 3);
                break;
            case DW_OP_deref: {
                auto addr = VirtualAddr{ stack.back() };
                stack.back() = proc.read_memory_as<std::uint64_t>(addr);
                break;
            }
            case DW_OP_deref_size: {
                auto addr = VirtualAddr{ stack.back() };
                auto size_to_read = cursor.u8();
                auto mem = proc.read_memory(addr, size_to_read);
                std::uint64_t res = 0;
                std::copy(
                    mem.data(), 
                    mem.data() + mem.size(),
                    reinterpret_cast<std::byte*>(&res)
                );
                stack.back() = res;
                break;
            }
            case DW_OP_xderef:
                zdb::Error::send("DW_OP_xderef not supported");
            case DW_OP_xderef_size:
                zdb::Error::send("DW_OP_xderef_size not supported");
            case DW_OP_push_object_address:
                zdb::Error::send("Unsupported opcode DW_OP_push_object_address");
            case DW_OP_form_tls_address:
                zdb::Error::send("Unsupported opcode DW_OP_form_tls_address");
            case DW_OP_call_frame_cfa:
                stack.push_back(regs.cfa().addr());
                break;
            case DW_OP_minus:
                binop(std::minus{});
                break;
            case DW_OP_mod:
                binop(std::modulus{});
                break;
            case DW_OP_mul:
                binop(std::multiplies{});
                break;
            case DW_OP_and:
                binop(std::bit_and{});
                break;
            case DW_OP_or:
                binop(std::bit_or{});
                break;
            case DW_OP_plus:
                binop(std::plus{});
                break;
            case DW_OP_shl:
                binop([](auto lhs, auto rhs) { return lhs << rhs; });
                break;
            case DW_OP_shr:
                // 逻辑位移: 只补0
                binop([](auto lhs, auto rhs) { return lhs >> rhs; });
                break;
            case DW_OP_shra:
                // 算数位移: 根据正负,补0 or
                binop([](auto lhs, auto rhs) { return static_cast<std::int64_t>(lhs) >> rhs; });
                break;
            case DW_OP_xor:
                binop(std::bit_xor{});
                break;
            case DW_OP_div: {
                auto rhs = static_cast<std::int64_t>(stack.back());
                stack.pop_back();
                auto lhs = static_cast<std::int64_t>(stack.back());
                stack.pop_back();
                stack.push_back(static_cast<std::uint64_t>(lhs / rhs));
                break;
            }
            case DW_OP_abs: {
                auto sval = static_cast<std::int64_t>(stack.back());
                sval = std::abs(sval);
                stack.back() = static_cast<std::uint64_t>(sval);
                break;
            }
            case DW_OP_neg: {
                auto neg = -static_cast<std::int64_t>(stack.back());
                stack.back() = static_cast<std::uint64_t>(neg);
                break;
            }
            case DW_OP_plus_uconst:
                stack.back() += cursor.uleb128();
                break;
            case DW_OP_not:
                stack.back() = ~stack.back();
                break;          
            case DW_OP_le:
                relop(std::less_equal{});
                break;
            case DW_OP_ge:
                relop(std::greater_equal{});
                break;
            case DW_OP_eq:
                relop(std::equal_to{});
                break;
            case DW_OP_lt:
                relop(std::less{});
                break;
            case DW_OP_gt:
                relop(std::greater{});
                break;
            case DW_OP_ne:
                relop(std::not_equal_to{});
                break;    
            case DW_OP_skip:
                cursor += cursor.s16();
                break;
            case DW_OP_bra:
                if (stack.back() != 0) {
                    cursor += cursor.s16();
                }
                stack.pop_back();
                break;
            case DW_OP_call2:
                zdb::Error::send("Unsupported opcode DW_OP_call2");
            case DW_OP_call4:
                zdb::Error::send("Unsupported opcode DW_OP_call4");
            case DW_OP_call_ref:
                zdb::Error::send("Unsupported opcode DW_OP_call_ref");     
            case DW_OP_regx: {
                uint64_t reg_id = cursor.uleb128();
                // 在栈上下文中,需要将寄存器值入栈
                if (in_frame_info_) {
                    Registers::Value reg_val = regs.read(find_register_info_by_dwarf_id(reg_id));
                    stack.push_back(std::get<std::uint64_t>(reg_val));
                }
                // 寄存器id为dwarf表达式结果
                else {
                    most_recent_location = register_result{ reg_id };
                }
            }
            case DW_OP_implicit_value: {
                uint64_t  length = cursor.uleb128();
                most_recent_location = data_result{ Span<const std::byte>{cursor.position(), length} };
                break;
            }
            case DW_OP_stack_value:
                result_is_address = false;
                break;
            case DW_OP_nop:
                break;
            case DW_OP_piece: {
                uint64_t byte_size = cursor.uleb128();
                simple_location loc = get_current_location();
                pieces.push_back(pieces_result::piece{ loc, byte_size * 8 });
                break;
            }
            case DW_OP_bit_piece: {
                uint64_t bit_size = cursor.uleb128();
                uint64_t offset = cursor.uleb128();
                simple_location loc = get_current_location();
                pieces.push_back(pieces_result::piece{ loc, bit_size, offset });
                break;
            }
            default:
                break;
            }
        }

        if (!pieces.empty()) {
            return pieces_result{ pieces };
        }

        return get_current_location();

    }

    zdb::DwarfExpression::result zdb::LocationList::eval(
        const zdb::Process& proc, 
        const Registers& regs
    ) const {
        VirtualAddr virt_pc = VirtualAddr{ regs.read_by_id_as<std::uint64_t>(RegisterId::rip) };
        FileAddr pc = virt_pc.to_file_addr(*parent_->elf());
        auto func = parent_->function_containing_address(pc);

        Cursor cursor({ expr_data_.begin(), expr_data_.end() });
        constexpr auto base_address_flag = ~static_cast<std::uint64_t>(0);
        uint64_t base_address = cu_->root()[DW_AT_low_pc].as_address().addr();

        uint64_t first = cursor.u64();
        uint64_t second = cursor.u64();
        while (!(first == 0 && second == 0)) {
            if (first == base_address_flag) {
                base_address = second;
            }
            else {
                uint16_t length = cursor.u16();
                if (pc.addr() >= base_address + first && pc.addr() < base_address + second) {
                    DwarfExpression expr(*parent_, { cursor.position(), cursor.position() + length }, in_frame_info_);
                    return expr.eval(proc, regs);
                }
                else {
                    cursor += length;
                }
            }
            first = cursor.u64();
            second = cursor.u64();
        }
    }
};

// For Dwarf&CompileUnit
namespace zdb {
    CompileUnit::CompileUnit(
        Dwarf &dwarf, 
        Span<const std::byte> data, 
        std::size_t abbrev_offset
    ) : parent_(&dwarf), data_(data), abbrev_offset_(abbrev_offset) {
        line_table_ = parse_line_table(*this);
    }

    Dwarf::Dwarf(const ELF &parent) : elf_(&parent) {
        compile_units_ = parse_compile_units(*this, parent);
        cfi_ = parse_call_frame_information(*this);
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
            DIE d = parse_die(*entry.cu, cur);
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
                Cursor cur({ entry.pos, entry.cu->data().end() });
                return parse_die(*entry.cu, cur);
            }
        );
        return found;
    }

    std::optional<zdb::DIE> zdb::Dwarf::find_global_variable(std::string name) const {
        index();
        auto it = global_variable_index_.find(name);
        if (it != global_variable_index_.end()) {
            Cursor cur({ it->second.pos, it->second.cu->data().end() });
            return parse_die(*it->second.cu, cur);
        }
        return std::nullopt;
    }

    std::vector<DIE> Dwarf::inline_stack_at_file_address(FileAddr address) const {
        auto func = function_containing_address(address);
        std::vector<DIE> inline_stack;
        if (func) {
            inline_stack.push_back(*func);
            while (true) {
                const auto& children = inline_stack.back().children();
                auto found = std::find_if(
                    children.begin(), 
                    children.end(),
                    [=](auto& child) {
                        return child.abbrev_entry()->tag == DW_TAG_inlined_subroutine 
                            && child.contains_file_address(address);
                    }
                );

                if (found == children.end()) {
                    break;
                } else { 
                    inline_stack.push_back(*found);
                }
            }
        }
        return inline_stack;
    }

    void Dwarf::index() const {
        if (!function_index_.empty()) {
            return;
        }
        for (auto& cu : compile_units_) {
            index_die(cu->root());
        }
    }

    void Dwarf::index_die(const DIE& current, bool in_function) const {
        bool has_range = 
            current.contains(DW_AT_low_pc) || current.contains(DW_AT_ranges);

        bool is_function = 
            current.abbrev_entry()->tag == DW_TAG_subprogram || current.abbrev_entry()->tag == DW_TAG_inlined_subroutine;
        if (has_range && is_function) {
            if (auto name = current.name(); name) {
                index_entry entry{ current.cu(), current.position() };
                function_index_.emplace(*name, entry);
            }
        }

        auto has_location = current.contains(DW_AT_location);
        auto is_variable = current.abbrev_entry()->tag == DW_TAG_variable;
        if (has_location && is_variable && !in_function) {
            // 有分配内存,是变量并且不在函数中,说明是全局变量
            if (auto name = current.name()) {
                index_entry entry{ current.cu(), current.position() };
                global_variable_index_.emplace(*name, entry);
            }
        }
        if (is_function) in_function = true;

        for (auto child : current.children()) {
            index_die(child, is_function);
        }
    }

    DIE CompileUnit::root() const {
        std::size_t header_size = 4 /*size*/ + 2 /*version*/ + 4 /*abbrev offset*/ + 1 /*address size*/;
        Cursor cursor({ data_.begin() + header_size, data_.end() });
        return parse_die(*this, cursor);
    }
}
