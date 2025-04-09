#ifndef LIBZDB_DWARF_HPP
#define LIBZDB_DWARF_HPP

#include <cstdint>
#include <libzdb/types.hpp>
#include <libzdb/bit.hpp>
#include <string_view>
#include <algorithm>
#include <vector>
#include <memory>
#include <libzdb/detail/dwarf.h>
#include <optional>
#include <libzdb/error.hpp>
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
        Cursor operator+=(std::size_t n) { pos_ += n; return *this; }
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
            auto null_terminator = std::find(pos_, data_.end(), std::byte{0});
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

// ----------------------------------- For Abbrev & DIE -------------------------------------------------- //
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
  class RangeList {
    public:
      RangeList(const CompileUnit* cu, Span<const std::byte> data, FileAddr base_address)
      : cu_(cu), data_(data), base_address_(base_address) {}
      struct Entry {
        FileAddr low;
        FileAddr high;

        bool contains(FileAddr addr) const {
          return low <= addr and addr < high;
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
        ) : parent_(&dwarf), data_(data), abbrev_offset_(abbrev_offset) {}

        const Dwarf* dwarf_info() const { return parent_; }
        Span<const std::byte> data() const { return data_; }

        const std::unordered_map<std::uint64_t, Abbrev>& abbrev_table() const;

        DIE root() const;

      private:
        Dwarf* parent_;
        Span<const std::byte> data_;
        std::size_t abbrev_offset_;
    };


    class Dwarf {
      public:
        Dwarf(const ELF &parent);
        const ELF* elf() const { return elf_; }

        const std::unordered_map<std::uint64_t, Abbrev> &get_abbrev_table(std::size_t offset);
        const std::vector<std::unique_ptr<CompileUnit>> &compile_units() const { return compile_units_; }

      private:
        const ELF *elf_;

        std::unordered_map<std::size_t, std::unordered_map<std::uint64_t, Abbrev>> abbrev_tables_;
        std::vector<std::unique_ptr<CompileUnit>> compile_units_;
    };
}

#endif
