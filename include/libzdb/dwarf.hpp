#ifndef LIBZDB_DWARF_HPP
#define LIBZDB_DWARF_HPP

#include <cstdint>
#include <libzdb/types.hpp>
#include <libzdb/bit.hpp>
#include <string_view>
#include <algorithm>
#include <vector>
#include <unordered_map>
#include <memory>
#include <libzdb/detail/dwarf.h>
#include <optional>
#include <libzdb/error.hpp>
#include <string>
#include <iostream>
#include <filesystem>
#include <libzdb/registers.hpp>

namespace {
    // `Cursor` type is to help us parse forms from various locations.
    // This cursor type will point to a location in the DWARF information,
    // allowing us to easily access information from that location. 
    // As a result, if we wanted to parse a ULEB128, a 64-bit integer, and then a string, we could
    // do something like the following:
    // ```cxx
    //  auto the_uleb = cur.uleb128();
    //  auto the_int = cur.u64();
    //  auto the_string = cur.string();
    // ```
    // The cursor will handle the parsing of the data and advance the location
    // being pointed to. Only the DWARF parser’s code will use this cursor type,
    // so we’ll make it private to the Dwarf class.
    class Cursor {
      public:
        explicit Cursor(zdb::Span<const std::byte> data)
          : data_(data), pos_(data.begin()) {}
        
        
        Cursor& operator++() { ++pos_; return *this; }
        Cursor& operator+=(std::size_t n) { pos_ += n; return *this; }
        const std::byte& operator*() const { return *pos_; }
        bool is_finished() const { return pos_ >= data_.end(); }
        const std::byte* position() { return pos_; }

        void skip_form(std::uint64_t form) {
          switch (form) {
          case DW_FORM_flag_present:
            break;
          case DW_FORM_data1:
          case DW_FORM_ref1:
          case DW_FORM_flag:
            pos_ += 1; break;
          case DW_FORM_data2:
          case DW_FORM_ref2:
            pos_ += 2; break;
          case DW_FORM_data4:
          case DW_FORM_ref4:
          case DW_FORM_ref_addr:
          case DW_FORM_sec_offset:
          case DW_FORM_strp:
            pos_ += 4; break;
          case DW_FORM_data8:
          case DW_FORM_addr:
            pos_ += 8; break;
          case DW_FORM_sdata:
            sleb128(); break;
          case DW_FORM_udata:
          case DW_FORM_ref_udata:
            uleb128(); break;
          case DW_FORM_block1:
            pos_ += u8(); break;
          case DW_FORM_block2:
            pos_ += u16(); break;
          case DW_FORM_block4:
            pos_ += u32(); break;
          case DW_FORM_block:
          case DW_FORM_exprloc:
            pos_ += uleb128(); break;
          case DW_FORM_string:
            while (!is_finished() && *pos_ != std::byte(0)) { ++pos_; }
            ++pos_;
            break;
          case DW_FORM_indirect:
            skip_form(uleb128()); break;
          default: zdb::Error::send("Unrecognized DWARF form");
          }
        }

        template<class T>
        T fixed_int() {
          auto result = zdb::from_bytes_as<T>(pos_);
          pos_ += sizeof(T);
          return result;
        }

        std::uint8_t u8() { return fixed_int<std::uint8_t>(); }
        std::uint16_t u16() { return fixed_int<std::uint16_t>(); }
        std::uint32_t u32() { return fixed_int<std::uint32_t>(); }
        std::uint64_t u64() { return fixed_int<std::uint64_t>(); }
        std::int8_t s8() { return fixed_int<std::int8_t>(); }
        std::int16_t s16() { return fixed_int<std::int16_t>(); }
        std::int32_t s32() { return fixed_int<std::int32_t>(); }
        std::int64_t s64() { return fixed_int<std::int64_t>(); }

        std::string_view string() {
            const std::byte* null_terminator = std::find(pos_, data_.end(), std::byte{0});
            std::string_view ret(reinterpret_cast<const char*>(pos_), null_terminator - pos_);
            pos_ = null_terminator + 1;
            return ret;
        }

        std::uint64_t uleb128() {
            std::uint64_t result = 0;
            std::uint64_t shift = 0;
            std::uint8_t byte;
            do {
                byte = u8();
                std::uint64_t value = static_cast<std::uint64_t>(byte & 0x7f);
                result |= value << shift;
                shift += 7;
            } while (byte & 0x80);

            return result;  
        }

        std::int64_t sleb128() {
            std::uint64_t result = 0;
            std::uint64_t shift = 0;
            std::uint8_t byte;
            do {
                byte = u8();
                std::uint64_t value = static_cast<std::uint64_t>(byte & 0x7f);
                result |= value << shift;
                shift += 7;
            } while (byte & 0x80);

            if (byte & 0x40 && shift < 64) {
                result |= (~static_cast<std::uint64_t>(0) << shift);
            }

            return static_cast<std::int64_t>(result);  
        }
        
      private:
        zdb::Span<const std::byte> data_;
        const std::byte *pos_;
    };
}

namespace zdb {
    class DIE;
    class CompileUnit;
    class ELF;
    class Dwarf;
    class RangeList;

// ----------------------------------- For `.eh_frame` and `.eh_frame_hdr` ------------------------//
    class CallFrameInformation {
      public:
        //          +-------------------+
        //          |       CIE         |
        //          |-------------------|
        //          | Common settings:  |
        //          | - Stack direction |
        //          | - Initial CFA rule|
        //          | - Return reg info |
        //          | - Encoding format |
        //          +---------+---------+
        //                    ^
        //    ----------------|----------------
        //    |               |               |
        //+---------+   +------------+   +------------+
        //|   FDE1  |   |    FDE2    |   |    FDE3    |
        //|---------|   |------------|   |------------|
        //| Code    |   | Code       |   | Code       |
        //| range   |   | range      |   | range      |
        //| CFA     |   | CFA rules  |   | CFA rules  |
        //| rules   |   | (specific) |   | (specific) |
        //+---------+   +------------+   +------------+


        // CIE (Common Information Entry):
        // A shared entry that contains common unwinding information 
        // used by multiple functions. It defines general rules such as:
        //   - Stack growth direction
        //   - Initial Canonical Frame Address (CFA) rule
        //   - Encoding format for call frame instructions
        //   - Default register saving/restoration rules
        // FDEs reference a CIE to inherit these common settings.
        struct common_information_entry {
            std::uint32_t length;
            std::uint64_t code_alignment_factor;
            std::int64_t data_alignment_factor;
            bool fde_has_augmentation;
            std::uint8_t fde_pointer_encoding;
            Span<const std::byte> instructions;
        };

        // FDE (Frame Description Entry):
        // A specific entry describing how to unwind the stack for a 
        // particular function or code range.
        // It contains:
        //   - Function address range (PC start and length)
        //   - Offset to the associated CIE
        //   - Function-specific CFA and register recovery rules
        // This allows proper stack unwinding during exceptions or debugging.
        struct frame_description_entry {
          std::uint32_t length;
          const common_information_entry* cie;
          FileAddr initial_location;
          std::uint64_t address_range;
          Span<const std::byte> instructions;
        };

        // `.eh_frame_hdr` contains a fast lookup table for FDEs.
        struct eh_hdr {
          const std::byte* start; // a pointer to the start of the `.eh_frame_hdr` section
          const std::byte* search_table; // a pointer to the start of the search table
          std::size_t count;  // the number of entries in search table
          std::uint8_t encoding; // entries’ encoding
          CallFrameInformation* parent;
          const std::byte* operator[](FileAddr address) const;  // takes an instruction’s object file offset 
                                                                // returns a pointer to the start of the FDE
                                                                // for that instruction.
        };

        CallFrameInformation() = delete;
        CallFrameInformation(const CallFrameInformation&) = delete;
        CallFrameInformation& operator=(const CallFrameInformation&) = delete;
        CallFrameInformation(const Dwarf* dwarf, eh_hdr hdr) : dwarf_(dwarf), eh_hdr_(hdr) {
          eh_hdr_.parent = this;
        }

        const Dwarf& dwarf() const { return *dwarf_; }
        const common_information_entry& get_cie(FileOffset at) const;
        Registers unwind(const Process& proc, FileAddr pc, Registers& regs) const;


      private:
        const Dwarf* dwarf_;
        eh_hdr eh_hdr_;

      private:
        mutable std::unordered_map<std::uint32_t, common_information_entry> cie_map_;
    };
      
// ----------------------------------- For `.debug_line ` -------------------------------------------------- //
    class LineTable {
      public:
        struct file {
          std::filesystem::path path;
          std::uint64_t modification_time;
          std::uint64_t file_length;
        };

        struct entry;

        LineTable(const LineTable&) = delete;
        LineTable& operator=(const LineTable&) = delete;
        LineTable(
          Span<const std::byte> data,
          const CompileUnit* cu,
          bool default_is_stmt, 
          std::int8_t line_base,
          std::uint8_t line_range, 
          std::uint8_t opcode_base,
          std::vector<std::filesystem::path> include_directories,
          std::vector<file> file_names
        ) : data_(data), 
        cu_(cu), 
        default_is_stmt_(default_is_stmt), 
        line_base_(line_base), 
        line_range_(line_range), 
        opcode_base_(opcode_base), 
        include_directories_(std::move(include_directories)), 
        file_names_(std::move(file_names)) {}

        const CompileUnit& cu() const { return *cu_; }
        const std::vector<file>& file_names() const { return file_names_; }

        class iterator;
        iterator begin() const;
        iterator end() const;

        iterator get_entry_by_address(FileAddr address) const;
        std::vector<iterator> get_entries_by_line(std::filesystem::path path, std::size_t line) const;

      private:
        Span<const std::byte> data_;
        const CompileUnit* cu_;
        bool default_is_stmt_;
        std::int8_t line_base_;
        std::uint8_t line_range_;
        std::uint8_t opcode_base_;
        std::vector<std::filesystem::path> include_directories_;
        mutable std::vector<file> file_names_;
    };

    struct LineTable::entry {
        FileAddr address;
        std::uint64_t file_index = 1;
        std::uint64_t line = 1;
        std::uint64_t column = 0;
        bool is_stmt;                   ///< Whether this instruction marks the beginning of a statement,
        bool basic_block_start = false;
        bool end_sequence = false;      ///< Whether this entry is special, and marks the byte immediately following a sequence of instructions
        bool prologue_end = false;      ///< Whether this instruction marks the end of the function prologue, and thus should be used for function-entry breakpoints. 
        bool epilogue_begin = false;    ///< Whether this instruction marks the beginning of the function epilogue, and thus should be used for function-exit breakpoints
        std::uint64_t discriminator = 0;
        file* file_entry = nullptr;

        bool operator==(const entry& rhs) const {
            return address == rhs.address 
                && file_index == rhs.file_index
                && line == rhs.line 
                && column == rhs.column
                && discriminator == rhs.discriminator;
      }
    };

    class LineTable::iterator {
      public:
        using value_type = entry; 
        using pointer = const entry*;
        using reference = const entry&;
        using difference_type = std::ptrdiff_t;
        using iterator_category = std::forward_iterator_tag;

        iterator(const LineTable* table_); 
        iterator() = default; 
        iterator(const iterator&) = default;

        iterator& operator=(const iterator&) = default;
        const LineTable::entry& operator*() const { return current_; } 
        const LineTable::entry* operator->() const { return &current_; }
        bool operator==(const iterator& rhs) const { return pos_ == rhs.pos_; } 
        bool operator!=(const iterator& rhs) const { return pos_ != rhs.pos_; }

        iterator& operator++(); 
        iterator operator++(int);

        bool execute_instruction();

      private:
        const LineTable* table_; 
        LineTable::entry current_;
        LineTable::entry registers_;
        const std::byte* pos_;
    };

// ----------------------------------- For Abbrev & DIE -------------------------------------------------- //
    struct SourceLocation {
        const LineTable::file* file;
        std::uint64_t line;
    };

    class Attr {
      public:
        Attr(const CompileUnit* cu, std::uint64_t type, std::uint64_t form, const std::byte* location) 
        : cu_(cu), type_(type), form_(form), location_(location) {}
      
        std::uint64_t name() const { return type_; }
        std::uint64_t form() const { return form_; }

        FileAddr as_address() const;
        std::uint32_t as_section_offset() const;
        Span<const std::byte> as_block() const;
        std::uint64_t as_int() const;
        std::string_view as_string() const;
        DIE as_reference() const;
        RangeList as_range_list() const;
        
      private:
        const CompileUnit* cu_;
        std::uint64_t type_;
        std::uint64_t form_;
        const std::byte* location_;
    };
    
    // DWARF Attribute Components Overview:
    //
    // When parsing a DIE (Debugging Information Entry), each attribute is defined
    // by three separate components, coming from different sources:
    //
    // | Component   | Source        | Meaning                                                 |
    // |-------------|---------------|---------------------------------------------------------|
    // | attr        | Abbrev table  | The attribute type (e.g., DW_AT_name, DW_AT_type)       |
    // | form        | Abbrev table  | How the attribute value is encoded (e.g., DW_FORM_strp) |
    // | value       | .debug_info   | The actual attribute data, interpreted using `form`     |
    //
    // - `attr` specifies what the attribute represents (e.g., name, type, location).
    // - `form` specifies how to decode the value from the binary stream.
    // - The value itself is stored in the .debug_info section, and is parsed
    //   based on the attribute's form defined in the abbreviation.
    //
    // The abbreviation table serves as a schema for interpreting the attribute values.

    struct AttrSpec {
      std::uint64_t attr;
      std::uint64_t form;
    };
    
    // Each Abbreviation entry structure:
    //  ULEB128 : `abbreviation code` to reference the table, if 0, end of table
    //  ULEB128 : `tag` for `DW_TAG_*`, found in `detail/dwarf.h`
    //  bool    : whether the DIE has child DIEs
    //  (ULEB128, ULEB128)* : list of attribute specifications, ends with (0, 0)
    struct Abbrev {
      std::uint64_t code;
      std::uint64_t tag;
      bool has_children;
      std::vector<AttrSpec> attr_specs;
    };

/**
 * .debug_info 
 *
 * CompileUnit(CU) Structure：
 *
 * ┌───────────────────────────────┐
 * │ header                        │
 * │ ├── cu_size                   │  // size
 * │ ├── cu_version                │  // DWARF version
 * │ ├── cu_abbrev_id              │  // Abbrev table entry ID
 * │ ├── addr_size                 │  // address size(8 for x64)
 * ├───────────────────────────────┤
 * │ data                          │
 * │ ├── abbrev_id1(DIE1)          │  
 * │ │   ├── attr1                 │  
 * │ │   ├── attr2                 │  
 * │ ├── abbrev_id2(DIE2)          │  
 * │ │   ├── attr1                 │  
 * │ ├── abbrev_id=0 (null DIE3)   │  
 * └───────────────────────────────┘
 *
 *  More than one DIE(Debugging Information Entry) exists in a compile unit.
 */
    class DIE {
      public:
        class ChildrenRange;
        ChildrenRange children() const;

      public:
        explicit DIE(const std::byte* next): next_(next) {} // Only for null DIE, Abbrev is 0

        DIE(
          const std::byte* pos, 
          const CompileUnit* cu, 
          const Abbrev* abbrev,
          std::vector<const std::byte*> attr_locs, 
          const std::byte* next
        ) : pos_(pos), cu_(cu), abbrev_(abbrev), attr_locs_(std::move(attr_locs)), next_(next) {}
        
        const CompileUnit* cu() const { return cu_; }
        const Abbrev* abbrev_entry() const { return abbrev_; }
        const std::byte* position() const { return pos_; }
        const std::byte* next() const { return next_; }

        bool contains(std::uint64_t attribute) const;
        Attr operator[](std::uint64_t attribute) const;

        FileAddr low_pc() const;
        FileAddr high_pc() const;
        bool contains_file_address(FileAddr address) const;

        std::optional<std::string_view> name() const;

        SourceLocation location() const;
        const LineTable::file& file() const;
        std::uint64_t line() const;


      private:
        const std::byte* pos_ = nullptr;
        const CompileUnit* cu_ = nullptr;       ///< A pointer to the compile unit to which it belongs
        const Abbrev* abbrev_ = nullptr;        ///< Abbreviation data in table entry
        const std::byte* next_ = nullptr;       ///< A pointer to the DIE immediately after this one, 
                                                ///< whether it be a child or a brother
        std::vector<const std::byte*> attr_locs_;
    };
    class DIE::ChildrenRange {
      public:
        ChildrenRange(DIE DIE) : die_(std::move(DIE)) {}
        class iterator {
          public:
            using value_type = DIE;
            using reference = const DIE&;
            using pointer = const DIE*;
            using difference_type = std::ptrdiff_t;
            using iterator_category = std::forward_iterator_tag;
            
            iterator() = default;
            iterator(const iterator&) = default;
            iterator& operator=(const iterator&) = default;
            explicit iterator(const DIE& die);
            const DIE& operator*() const { return *op_die_; }
            const DIE* operator->() const { return &op_die_.value(); }
            iterator& operator++();
            iterator operator++(int);
            bool operator==(const iterator& rhs) const;
            bool operator!=(const iterator& rhs) const { return !(*this == rhs); }

          private:
            std::optional<DIE> op_die_;
        };

        iterator begin() const {
          if (die_.abbrev_->has_children) {
            return iterator{ die_ };
          }
          return end();
        }
        iterator end() const { return iterator{}; }
      private:
        DIE die_;
    };

// ----------------------------------- For `.debug_range` Section ----------------------------------------- //
  // The `.debug_range` section consists of a series of entries of three possible kinds.
  // All range list entries consistof two integers with a byte size identical the address size of the machine (8 bytes, on x64).
  // 
  // 1. `base address selectors`; 
  //  - An integer with all bits set, which indicates that this entry is a base address selector
  //  - An integer that sets the base address from which all future range list entries should be considered 
  //      an offset (until the base address is changed again or the list ends)
  // 
  // 2. `Regular entries selectors`, which change how we should interpret regular entries; 
  //  - A beginning address offset relative to the current base address
  //  - An ending address offset relative to the current base `base address selectors`
  // Note: If no base address selector entry precedes the current one, the base address 
  //  gets encoded as the `DW_AT_low_pc` attribute in the DIE that is referencing the range list. 
  //  Such a DIE will have a `DW_AT_low_pc` attribute, but not a matching `DW_AT_high_pc` attribute.
  //
  // 3. An `end-of-list indicator` has both integers set to 0.
  class RangeList {
    public:
      RangeList(const CompileUnit* cu, Span<const std::byte> data, FileAddr base_address)
      : cu_(cu), data_(data), base_address_(base_address) {}
      struct Entry {
        FileAddr low;
        FileAddr high;

        bool contains(FileAddr addr) const {
          return low <= addr && addr < high;
        }
      };

      class iterator;
      iterator begin() const;
      iterator end() const;
      bool contains(FileAddr address) const;

    private:
      const CompileUnit* cu_;
      Span<const std::byte> data_;
      FileAddr base_address_;
  };

  class RangeList::iterator {
    public:
      using value_type = Entry;
      using reference = const Entry&;
      using pointer = const Entry*;
      using difference_type = std::ptrdiff_t;
      using iterator_category = std::forward_iterator_tag;

      iterator(const CompileUnit* cu, Span<const std::byte> data, FileAddr base_address);
      iterator() = default;
      iterator(const iterator&) = default;

      iterator& operator=(const iterator&) = default;
      const Entry& operator*() const { return current_; }
      const Entry* operator->() const { return &current_; }
      bool operator==(iterator rhs) const { return pos_ == rhs.pos_; }
      bool operator!=(iterator rhs) const { return pos_ != rhs.pos_; }
      iterator& operator++();
      iterator operator++(int);

    private:
      const CompileUnit* cu_ = nullptr;
      Span<const std::byte> data_{ nullptr,nullptr };
      FileAddr base_address_;
      const std::byte* pos_ = nullptr;
      Entry current_;
  };


// ----------------------------------- For `.debug_info` Section ------------------------------------------ //

    // We won’t worry about making the range type conform to the expectations of C++20 ranges, 
    // and will instead err on the side of simplicity. The zdb::DIE::children_range type will wrap a DIE 
    // and provide begin and end member functions that we can call to retrieve iterators to the children. 
    // This will allow us to write code like the following:
    // ```
    //  for (auto child : my_die.children()) {
    //    do_something(child);
    //  }
    // ```

    

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
    //      on the system (eight, in our case)
    class CompileUnit {
      public:
        CompileUnit(
          Dwarf &dwarf, 
          Span<const std::byte> data, 
          std::size_t abbrev_offset
        );

        const Dwarf* dwarf_info() const { return parent_; }
        Span<const std::byte> data() const { return data_; }
        const LineTable& lines() const { return *line_table_; }

        const std::unordered_map<std::uint64_t, Abbrev>& abbrev_table() const;

        DIE root() const;

      private:
        Dwarf* parent_;
        Span<const std::byte> data_;
        std::size_t abbrev_offset_;
        std::unique_ptr<LineTable> line_table_;
    };


    class Dwarf {
      public:
        Dwarf(const ELF &parent);
        const ELF* elf() const { return elf_; }

        const CompileUnit* compile_unit_containing_address(FileAddr address) const;
        std::optional<DIE> function_containing_address(FileAddr address) const;
        std::vector<DIE> find_functions(std::string name) const;
        std::vector<DIE> inline_stack_at_file_address(FileAddr address) const;

        const std::unordered_map<std::uint64_t, Abbrev> &get_abbrev_table(std::size_t offset);
        const std::vector<std::unique_ptr<CompileUnit>> &compile_units() const { return compile_units_; }
        const CallFrameInformation& cfi() const { return *cfi_; }

        LineTable::iterator line_entry_at_address(FileAddr address) const {
          auto cu = compile_unit_containing_address(address);
          if (!cu) return {};
          return cu->lines().get_entry_by_address(address);
        }
        

      private:
        void index() const;
        void index_die(const DIE& current) const;

        struct index_entry {
          const CompileUnit* cu;
          const std::byte* pos;
        };
        mutable std::unordered_multimap<std::string, index_entry> function_index_;

      private:
        const ELF *elf_;
        std::unique_ptr<CallFrameInformation> cfi_;

        std::unordered_map<std::size_t, std::unordered_map<std::uint64_t, Abbrev>> abbrev_tables_;
        std::vector<std::unique_ptr<CompileUnit>> compile_units_;
    };
}

#endif
