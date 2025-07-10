#ifndef SDB_TYPE_HPP
#define SDB_TYPE_HPP

#include <string_view>
#include <optional>
#include <libzdb/dwarf.hpp>

namespace zdb {
class Process;

class Type {
  public:
    Type(DIE die): die_(std::move(die)) {}

    DIE get_die() const { return die_; }
    std::size_t byte_size() const;
    bool is_char_type() const;

    // 剥离类型的限定符
    template<int... Tags>
    Type strip() const {
        auto ret = *this;
        auto tag = ret.get_die().abbrev_entry()->tag;
        while (((tag == Tags) || ...)) {
            ret = ret.get_die()[DW_AT_type].as_type().get_die();
            tag = ret.get_die().abbrev_entry()->tag;
        }
        return ret;
    }

    Type strip_cv_typedef() const {
        return strip<DW_TAG_const_type,
        DW_TAG_volatile_type,
        DW_TAG_typedef>();
    }

    Type strip_cvref_typedef() const {
        return strip<DW_TAG_const_type,
        DW_TAG_volatile_type,
        DW_TAG_typedef,
        DW_TAG_reference_type,
        DW_TAG_rvalue_reference_type>();
    }

    Type strip_all() const {
        return strip<DW_TAG_const_type,
        DW_TAG_volatile_type,
        DW_TAG_typedef,
        DW_TAG_reference_type,
        DW_TAG_rvalue_reference_type,
        DW_TAG_pointer_type>();
    }

  private:
    std::size_t compute_byte_size() const;
    DIE die_;
    mutable std::optional<std::size_t> byte_size_;
};

class TypedData {
  public:
    TypedData(
        std::vector<std::byte> data, 
        Type value_type,
        std::optional<VirtualAddr> address = std::nullopt
    ): data_(std::move(data)), type_(value_type), address_(address) {}

    const std::vector<std::byte>& data() const { return data_; }
    const std::byte* data_ptr() const { return data_.data(); }
    const Type& value_type() const { return type_; }
    std::optional<VirtualAddr> address() const { return address_; }

    TypedData fixup_bitfield(
        const Process& proc, 
        const DIE& member_die
    ) const;
    std::string visualize(const Process& proc, int depth = 0) const;
  
    // for Target::resolve_indirect_name::a->b 
    TypedData deref_pointer(const zdb::Process& proc) const;

    // for Target::resolve_indirect_name::a.b
    TypedData read_member(
      const zdb::Process& proc,
      std::string_view member_name
    ) const;

    // for Target::resolve_indirect_name::a[b]
    TypedData index(
      const zdb::Process& proc,
      std::size_t index
    ) const;

  private:
    std::vector<std::byte> data_;
    Type type_;
    std::optional<VirtualAddr> address_;
};
}

#endif