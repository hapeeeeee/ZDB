#ifndef SDB_TYPE_HPP
#define SDB_TYPE_HPP

#include <string_view>
#include <optional>
#include <libzdb/dwarf.hpp>

namespace zdb {
class Process;

enum class BuiltinType {
  string, 
  character, 
  integer, 
  boolean, 
  floating_point
};

// 调试器调用函数时，需要传递的参数类型
enum class ParameterClass {
  integer,      // 在通用寄存器（GPR）中传递和返回的类型
  sse,          // 在xmm寄存器的低8个字节中传递和返回的类型
  sseup,        // 在xmm寄存器的高位字节中传递和返回的类型
  x87,          // 在st寄存器的低8个字节中返回的类型
  x87up,        // 在st寄存器的前2个字节中返回的类型
  complex_x87,  // 在两个st寄存器中返回的类型（虚数）
  memory,       // 在堆栈上传递和返回的类型
  no_class,     // 用作填充、空结构和联合的默认类
};

class Type {
  public:
    Type(DIE die): info_(std::move(die)) {}
    Type(BuiltinType ty): info_(ty) {}

    DIE get_die() const { 
		if (!std::holds_alternative<DIE>(info_)) {
			zdb::Error::send("Type is not from DWARF info");
		}
      return std::get<DIE>(info_);
    }

    BuiltinType get_builtin_type() const {
      if (!std::holds_alternative<BuiltinType>(info_)) {
        Error::send("Type is not a builtin type");
      }
      return std::get<BuiltinType>(info_);
    }

    std::size_t byte_size() const;

    bool is_char_type() const;
    bool is_class_type() const;
    bool is_reference_type() const;
	  bool is_from_dwarf() const { return std::holds_alternative<DIE>(info_); }

    // ------------------------- 函数调用时传递参数所需的规则 ----------------------
    // 计算参数的预期对齐
    std::size_t alignment() const;
    // 检查参数是否有未对齐的字段
    bool has_unaligned_fields() const;
    // 检查参数是否为NTFPOC. 对于NTFPOC类型，只支持指针传递
    // NTFPOC定义详见docs/NTFPOC.md
    bool is_non_trivial_for_calls() const;
    // 不支持传递像__m256这样的向量类型，只需要为任何给定的类型考虑2个八字节，
    // 返回一个包含两个参数类的数组，每个八字节一个。
    std::array<ParameterClass, 2> get_parameter_classes() const;
    // --------------------------------------------------------------------------


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

    bool operator==(const Type& rhs) const;
    bool operator!=(const Type& rhs) const {
      return !(*this == rhs);
    }

  private:
    std::size_t compute_byte_size() const;
    std::variant<DIE, BuiltinType> info_;
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