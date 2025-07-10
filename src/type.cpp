#include <libzdb/type.hpp>
#include <fmt/format.h>
#include <libzdb/process.hpp>
#include <numeric>

namespace {
    std::string visualize_base_type(const zdb::TypedData& data) {
        auto& type = data.value_type();
        auto die = type.get_die();
        auto ptr = data.data_ptr();

        switch (die[DW_AT_encoding].as_int()) {
        case DW_ATE_boolean:
            return zdb::from_bytes_as<bool>(ptr) ? "true" : "false";
        case DW_ATE_float: {
            if (die.name() == "float")
                return fmt::format("{}", zdb::from_bytes_as<float>(ptr));
            if (die.name() == "double")
                return fmt::format("{}", zdb::from_bytes_as<double>(ptr));
            if (die.name() == "long double")
                return fmt::format("{}", zdb::from_bytes_as<long double>(ptr));
            zdb::Error::send("Unsupported floating point type");
        }
        case DW_ATE_signed: {
            switch (type.byte_size()) {
                case 1: return fmt::format("{}", zdb::from_bytes_as<std::int8_t>(ptr));
                case 2: return fmt::format("{}", zdb::from_bytes_as<std::int16_t>(ptr));
                case 4: return fmt::format("{}", zdb::from_bytes_as<std::int32_t>(ptr));
                case 8: return fmt::format("{}", zdb::from_bytes_as<std::int64_t>(ptr));
                default: zdb::Error::send("Unsupported signed integer size");
            }
        }
        case DW_ATE_unsigned: {
            switch (type.byte_size()) {
                case 1: return fmt::format("{}", zdb::from_bytes_as<std::uint8_t>(ptr));
                case 2: return fmt::format("{}", zdb::from_bytes_as<std::uint16_t>(ptr));
                case 4: return fmt::format("{}", zdb::from_bytes_as<std::uint32_t>(ptr));
                case 8: return fmt::format("{}", zdb::from_bytes_as<std::uint64_t>(ptr));
                default: zdb::Error::send("Unsupported signed integer size");
            }
        }
        case DW_ATE_signed_char:
            return fmt::format("{}", zdb::from_bytes_as<signed char>(ptr));
        case DW_ATE_unsigned_char:
            return fmt::format("{}", zdb::from_bytes_as<unsigned char>(ptr));
        case DW_ATE_UTF:
            zdb::Error::send("DW_ATE_UTF is not implemented");
        default:
            zdb::Error::send("Unsupported encoding");

        }
    }

    std::string visualize_member_pointer_type(const zdb::TypedData& data) {
        return fmt::format(
            "0x{:x}",
            zdb::from_bytes_as<std::uintptr_t>(data.data_ptr())
        );
    }

    std::string visualize_subrange(
        const zdb::Process& proc, 
        const zdb::Type& value_type,
        zdb::Span<const std::byte> data, 
        std::vector<std::size_t> dimensions
    ) {
        if (dimensions.empty()) {
            std::vector<std::byte> data_vec { data.begin(), data.end() };
            return zdb::TypedData{ std::move(data_vec), value_type }.visualize(proc);
        }

        std::string result = "[";
        std::size_t size = dimensions.back();
        dimensions.pop_back();
        auto sub_size = std::accumulate(
            dimensions.begin(), 
            dimensions.end(),
            value_type.byte_size(), 
            std::multiplies<>()
        );

        for (std::size_t i = 0; i < size; ++i) {
            zdb::Span<const std::byte> subdata{ data.begin() + i * sub_size, data.end() };
            result += visualize_subrange(proc, value_type, subdata, dimensions);
            if (i != size - 1) {
                result += ", ";
            }
        }
        return result + "]";

    }

    std::string visualize_array_type(const zdb::Process& proc, const zdb::TypedData& data) {
        std::vector<std::size_t> dimensions;
        for (auto& child : data.value_type().get_die().children()) {
            if (child.abbrev_entry()->tag == DW_TAG_subrange_type) {
                dimensions.push_back(child[DW_AT_upper_bound].as_int() + 1);
            }
        }
        std::reverse(dimensions.begin(), dimensions.end());
        auto value_type = data.value_type().get_die()[DW_AT_type].as_type();
        return visualize_subrange(proc, value_type, data.data(), dimensions);
    }

    std::string visualize_pointer_type(
        const zdb::Process& proc, 
        const zdb::TypedData& data
    ) {
        std::uint64_t ptr = zdb::from_bytes_as<std::uint64_t>(data.data_ptr());
        if (ptr == 0) return "0x0";
        if (data.value_type().get_die()[DW_AT_type].as_type().is_char_type()) {
            return fmt::format(
                "\"{}\"", 
                proc.read_string(zdb::VirtualAddr{ ptr })
            );
        }
        return fmt::format("0x{:x}", ptr);
    }

    std::string visualize_class_type(
        const zdb::Process& proc, 
        const zdb::TypedData& data,
        int depth
    ) {
        std::string result = "{\n";
        for (auto &child : data.value_type().get_die().children()) {
            if (child.abbrev_entry()->tag == DW_TAG_member
                && (child.contains(DW_AT_data_member_location) 
                || child.contains(DW_AT_bit_offset))
            ) {
                auto indent = std::string(depth + 1, '\t');
                auto child_byte_offset = child.contains(DW_AT_data_member_location) ?
                    child[DW_AT_data_member_location].as_int() :
                    child[DW_AT_data_bit_offset].as_int() / 8;
                zdb::Type child_type = child[DW_AT_type].as_type();
                const std::byte* child_ptr = data.data_ptr() + child_byte_offset;
                std::vector<std::byte> child_native_data = std::vector<std::byte>{child_ptr, child_ptr + child_type.byte_size()};
                zdb::TypedData child_data = zdb::TypedData{child_native_data, child_type}
                    .fixup_bitfield(proc, child);
                std::string child_str = child_data.visualize(proc, depth + 1);
                std::string_view name = child.name().value_or("<unnamed>");
                result += fmt::format("{}{}: {}\n", indent, name, child_str);
            }
        }
        auto indent = std::string(depth, '\t');
        result += indent + "}";
        return result;
    }
};

std::size_t zdb::Type::byte_size() const {
    if (!byte_size_.has_value()) {
        byte_size_ = compute_byte_size();
    }
    return *byte_size_;
}

std::size_t zdb::Type::compute_byte_size() const {
    auto tag = die_.abbrev_entry()->tag;

    if (tag == DW_TAG_pointer_type) {
        return 8;
    }

    // 如果类型是指向成员的指针·，则大小取决于它指向的类型。
    // 在Linux系统上，指向成员函数的指针实际上是指向成员数
    // 据的指针的两倍大，因为它们存储了用于支持多重继承的
    // 额外8个字节。您可以在C++ ABI上看到相关细节
    if (tag == DW_TAG_ptr_to_member_type) {
        auto member_type = die_[DW_AT_type].as_type();
        if (member_type.get_die().abbrev_entry()->tag == DW_TAG_subroutine_type) {
            return 16;
        }
        return 8;
    }

    // 数组DIE具有类型DW_TAG_subrange_type的子类型，用于指定数组的
    // 每个维度的边界，以及指定数组元素类型的DW_AT_type属性。
    // 我们通过首先计算类型DIE的DW_AT_type的字节大小来计算数组类型的字节大小
    // 将此大小乘以每个维度的大小（即1加上DW_AT_upper_bound属性的值）。
    if (tag == DW_TAG_array_type) {
        auto value_size = die_[DW_AT_type].as_type().byte_size();
        for (auto& child : die_.children()) {
            if (child.abbrev_entry()->tag == DW_TAG_subrange_type) {
                value_size *= child[DW_AT_upper_bound].as_int() + 1;
            }
        }
        return value_size;
    }

    if (die_.contains(DW_AT_byte_size)) {
        return die_[DW_AT_byte_size].as_int();
    }
    if (die_.contains(DW_AT_type)) {
        return die_[DW_AT_type].as_type().byte_size();
    }
    return 0;
}

bool zdb::Type::is_char_type() const {
    auto stripped = strip_cv_typedef().get_die();
    if (!stripped.contains(DW_AT_encoding)) {
        return false;
    }
    auto encoding = stripped[DW_AT_encoding].as_int();
    return stripped.abbrev_entry()->tag == DW_TAG_base_type 
        && (encoding == DW_ATE_signed_char || encoding == DW_ATE_unsigned_char);
}

zdb::TypedData zdb::TypedData::fixup_bitfield(
    const zdb::Process& proc,
    const zdb::DIE& member_die
) const {
    zdb::Type stripped_type = type_.strip_cv_typedef();
    auto bit_filed_info = member_die.get_bitfield_information(stripped_type.byte_size());
    if (!bit_filed_info) {
        return *this;
    }

    auto [bit_size, storage_byte_size, bit_offset] = *bit_filed_info;
    std::vector<std::byte> fixed_data;
    fixed_data.resize(storage_byte_size);

    auto dest = reinterpret_cast<std::uint8_t*>(fixed_data.data());
    auto src = reinterpret_cast<const std::uint8_t*>(data_.data());
    memcpy_bits(dest, 0, src, bit_offset, bit_size);
    return { fixed_data, type_ };
}

std::string zdb::TypedData::visualize(
    const zdb::Process& proc, 
    int depth
) const {
    auto die = type_.get_die();
    switch (die.abbrev_entry()->tag) {
    case DW_TAG_base_type:
        return visualize_base_type(*this);
    case DW_TAG_pointer_type:
        return visualize_pointer_type(proc, *this);
    case DW_TAG_ptr_to_member_type:
        return visualize_member_pointer_type(*this);
    case DW_TAG_array_type:
        return visualize_array_type(proc, *this);
    case DW_TAG_class_type:
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
        return visualize_class_type(proc, *this, depth);
    case DW_TAG_enumeration_type:
    case DW_TAG_typedef:
    case DW_TAG_const_type:
    case DW_TAG_volatile_type:
        return zdb::TypedData{ data_, die[DW_AT_type].as_type() }.visualize(proc);
    default: zdb::Error::send("Unsupported type");
    }
}

// for Target::resolve_indirect_name::a->b 
zdb::TypedData zdb::TypedData::deref_pointer(const zdb::Process& proc) const {
    zdb::DIE stripped_die = type_.strip_cv_typedef().get_die();
    if (stripped_die.abbrev_entry()->tag != DW_TAG_pointer_type) {
        Error::send("Not a pointer type");
    }

    VirtualAddr addr = VirtualAddr{ from_bytes_as<std::uint64_t>(data_.data()) } ;
    Type value_type = stripped_die[DW_AT_type].as_type();
    auto derefed_type_data = proc.read_memory(
        addr, 
        value_type.byte_size()
    );

    return { std::move(derefed_type_data), value_type, addr };
}

// for Target::resolve_indirect_name::a.b
zdb::TypedData zdb::TypedData::read_member(
    const zdb::Process& proc,
    std::string_view member_name
) const {
    DIE die = type_.get_die();
    auto children = die.children();
    auto it = std::find_if(
        children.begin(), 
        children.end(), 
        [&](const DIE& child) {
            return child.name().value_or("") == member_name;
        }
    );

    if (it == children.end()) {
        zdb::Error::send("No such member");
    }

    zdb::DIE var_die = *it;
    Type value_type = var_die[DW_AT_type].as_type();
    uint64_t byte_offset = var_die.contains(DW_AT_data_member_location) ?
        var_die[DW_AT_data_member_location].as_int():
        var_die[DW_AT_data_bit_offset].as_int() / 8;
    auto data_start = data_.begin() + byte_offset;
    
    std::vector<std::byte> member_data{ data_start, data_start + value_type.byte_size() };
    auto data = address_ ?
        TypedData{ std::move(member_data), value_type, *address_ + byte_offset } :
        TypedData{ std::move(member_data), value_type };
    return data.fixup_bitfield(proc, var_die);

}

// for Target::resolve_indirect_name::a[b]
zdb::TypedData zdb::TypedData::index(
    const zdb::Process& proc,
    std::size_t index
) const {
    DIE parent_type_die = type_.strip_cv_typedef().get_die();
    uint64_t parent_tag = parent_type_die.abbrev_entry()->tag;
    if (parent_tag != DW_TAG_array_type 
        && parent_tag != DW_TAG_pointer_type
    ) {
        Error::send("Not pointer or array type");
    } 
    Type element_type = parent_type_die[DW_AT_type].as_type();
    std::size_t element_size = element_type.byte_size();
    std::size_t element_offset = element_size * index;
    if (parent_tag == DW_TAG_pointer_type) {
        VirtualAddr addr = VirtualAddr {from_bytes_as<std::uint64_t>(data_.data())};
        addr += element_offset;
        std::vector<std::byte> element_data = proc.read_memory(addr, element_size);
        return { std::move(element_data), element_type, addr };
    } 
    else {
        std::vector<std::byte> element_data{
            data_.begin() + element_offset,
            data_.begin() + element_offset + element_size 
        };

        if (address_) {
            return { std::move(element_data), element_type, *address_ + element_offset };
        }
        return { std::move(element_data), element_type };
    }
}