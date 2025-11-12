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


    // 如果类型大于8个八字节或包含未与预期边界对齐的字段，则将其指定为MEMORY类。
    // 该类的每个八字节都单独分类。属于给定八字节的每个字段都将按照以下规则分类
    // 并合并到该八字节的单个类中，这些规则从上到下运行：
    //  - 如果两个类相同，则结果是这个类。
    //  - 如果其中一个类为NO_CLASS，则结果为另一个类。
    //  - 如果其中一个类是MEMORY，则结果是MEMORY。
    //  - 如果其中一个类是INTEGER，则结果是INTEGER。
    //  - 如果其中一个类是X87、X87UP或COMPLEX_X87，则结果是MEMORY。
    //  - 除此之外，返回SSE
    zdb::ParameterClass merge_parameter_classes(
        zdb::ParameterClass lhs, 
        zdb::ParameterClass rhs
    ) {
        using namespace zdb;
        if (lhs == rhs) return lhs;
        if (lhs == ParameterClass::no_class) return rhs;
        if (rhs == ParameterClass::no_class) return lhs;
        if (lhs == ParameterClass::memory
            || rhs == ParameterClass::memory
        ) {
            return ParameterClass::memory;
        }

        if (lhs == ParameterClass::integer
            || rhs == ParameterClass::integer
        ) {
            return ParameterClass::integer;
        }

        if (lhs == ParameterClass::x87
            || rhs == ParameterClass::x87
            || lhs == ParameterClass::x87up
            || rhs == ParameterClass::x87up
            || lhs == ParameterClass::complex_x87
            || rhs == ParameterClass::complex_x87
        ) {
            return ParameterClass::memory;
        }

        return ParameterClass::sse;
    }

    void classify_class_field(
        const zdb::Type& type,
        const zdb::DIE& field,
        std::array<zdb::ParameterClass, 2>& classes,
        int bit_offset
    ) {
        auto bitfield_info = field.get_bitfield_information(type.byte_size());
        auto field_type = field[DW_AT_type].as_type();

        auto all_byte_size = bitfield_info ? 
            bitfield_info->bit_size:
            field_type.byte_size();
        
        auto current_bit_offset = bitfield_info ?
            bitfield_info->bit_offset + bit_offset:
            field[DW_AT_data_member_location].as_int() * 8 + bit_offset;

        // current_eight_index只会是0或者1，因为大于16字节的类类型，
        // 在classify_class_type被设置为了2个memory类型
        auto current_eight_index = current_bit_offset / 64;

        if (field_type.is_class_type()) {
            for (auto child : field_type.get_die().children()) {
                if (child.abbrev_entry()->tag == DW_TAG_member
                    && (child.contains(DW_AT_data_member_location)
                    || child.contains(DW_AT_data_bit_offset))
                ) {
                    classify_class_field(type, child, classes, current_bit_offset);
                }
            }
        } else {
            auto field_class = field_type.get_parameter_classes();
            // current_eight_index只会是0或者1, 
            //  - index = 0: 将对应下标(2个0和2个1)处合并
            //  - index = 1: merge(classes[1], field_classes[0])，
            //              因为父亲都到第二个8字节了，所以field也最多只有一个8字节
            classes[current_eight_index] = merge_parameter_classes(
                classes[current_eight_index],
                field_class[0]
            );

            if (current_eight_index == 0) {
                classes[1] = merge_parameter_classes(classes[1], field_class[1]);
            }
        }
    }

    std::array<zdb::ParameterClass, 2> classify_class_type(const zdb::Type& type) {
        if (type.is_non_trivial_for_calls()) {
            zdb::Error::send("NTFPOC types are not supported");
        }

        // 如果太大或字段未对齐，则直接按内存传
        if (type.has_unaligned_fields() || type.byte_size() > 16) {
            return {
                zdb::ParameterClass::memory,
                zdb::ParameterClass::memory
            };
        }

        std::array<zdb::ParameterClass, 2> classes {
            zdb::ParameterClass::no_class,
            zdb::ParameterClass::no_class
        };

        // 将数组看作指向它元素类型的指针，因此里面放的是什么类型，按这个类型分类就行。长一点就复制用两块。
        if (type.get_die().abbrev_entry()->tag == DW_TAG_array_type) {
            zdb::Type elem_type = type.get_die()[DW_AT_type].as_type();
            classes = elem_type.get_parameter_classes();
            if (type.byte_size() > 8 && classes[1] == zdb::ParameterClass::no_class) {
                classes[1] = classes[0];
            }
        } 
        else {
            for (auto child : type.get_die().children()) {
                if (child.abbrev_entry()->tag == DW_TAG_member 
                    && (child.contains(DW_AT_data_member_location) 
                    || child.contains(DW_AT_data_bit_offset))
                ) {
                    classify_class_field(type, child, classes, 0);
                }
            }
        }

        if (classes[0] == zdb::ParameterClass::memory
            || classes[1] == zdb::ParameterClass::memory
        ) {
            classes[0] = classes[1] = zdb::ParameterClass::memory;
        }
        else if (classes[1] == zdb::ParameterClass::x87up
            && classes[0] != zdb::ParameterClass::x87
        ) {
            classes[0] = classes[1] = zdb::ParameterClass::memory;
        }

        return classes;
    }

    bool is_destructor(const zdb::DIE& func) {
        auto name = func.name();
        return name
            && name.value().size() > 1
            && name.value()[0] == '~';
    }

    // class MyClass {
    // public:
    //     MyClass(const MyClass&);        // 拷贝构造函数
    //     MyClass(MyClass&&);             // 移动构造函数
    // };
    bool is_copy_or_move_constructor(
        const zdb::Type& class_type, 
        const zdb::DIE& func
    ) {
        auto class_name = class_type.get_die().name();
        if (class_name != func.name()) return false;

        int i = 0;
        for (auto child : func.children()) {
            if (child.abbrev_entry()->tag == DW_TAG_formal_parameter) {
                if (i == 0) {
                    auto child_type = child[DW_AT_type].as_type();
                    // this指针
                    if (child_type.get_die().abbrev_entry()->tag != DW_TAG_pointer_type)
                        return false;
                    // this指针指向自己类类型
                    if (child_type.get_die()[DW_AT_type].as_type().strip_cv_typedef() != class_type)
                        return false;
                } 
                else if (i == 1) {
                    auto child_type = child[DW_AT_type].as_type();
                    auto tag = child_type.get_die().abbrev_entry()->tag;

                    if (tag != DW_TAG_reference_type && tag != DW_TAG_rvalue_reference_type)
                        return false;

                    auto ref = child_type.get_die()[DW_AT_type].as_type().strip_cv_typedef();
                    if (ref != class_type)
                        return false;
                } else {
                    return false;
                }
            }
            i++;
        }
        return i == 2;
    }
};

std::size_t zdb::Type::byte_size() const {
    if (!byte_size_.has_value()) {
        byte_size_ = compute_byte_size();
    }
    return *byte_size_;
}

std::size_t zdb::Type::compute_byte_size() const {
    if (!is_from_dwarf()) {
        switch (get_builtin_type()) {
            case BuiltinType::boolean: return 1;
            case BuiltinType::character: return 1;
            case BuiltinType::integer: return 8;
            case BuiltinType::floating_point: return 8;
            case BuiltinType::string: return 8;
        }
    }

    auto& die_ = std::get<DIE>(info_);
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

bool zdb::Type::is_class_type() const {
    if (!is_from_dwarf()) return false;
    auto stripped = strip_cv_typedef().get_die();
    auto tag = stripped.abbrev_entry()->tag;

    return tag == DW_TAG_class_type
        || tag == DW_TAG_structure_type
        || tag == DW_TAG_union_type;
}

bool zdb::Type::is_reference_type() const {
    if (!is_from_dwarf()) return false;
    auto stripped = strip_cv_typedef().get_die();
    auto tag = stripped.abbrev_entry()->tag;
    return tag == DW_TAG_reference_type
        || tag == DW_TAG_rvalue_reference_type;
}


bool zdb::Type::operator==(const Type& rhs) const {
    if (!is_from_dwarf() && !rhs.is_from_dwarf()) {
        return get_builtin_type() == rhs.get_builtin_type();
    }

    const Type* from_dwarf = nullptr;
    const Type* builtin = nullptr;
    if (!is_from_dwarf()) {
        from_dwarf = &rhs;
        builtin = this;
    }
    else if (!rhs.is_from_dwarf()) {
        from_dwarf = this;
        builtin = &rhs;
    }

    if (from_dwarf && builtin) {
        auto die = from_dwarf->strip_cvref_typedef().get_die();
        auto tag = die.abbrev_entry()->tag;
        if (tag == DW_TAG_base_type) {
            switch (die[DW_AT_encoding].as_int()) {
                case DW_ATE_boolean:
                    return builtin->get_builtin_type() == BuiltinType::boolean;
                case DW_ATE_float:
                    return builtin->get_builtin_type() == BuiltinType::floating_point;
                case DW_ATE_signed:
                case DW_ATE_unsigned:
                    return builtin->get_builtin_type() == BuiltinType::integer;
                case DW_ATE_signed_char:
                case DW_ATE_unsigned_char:
                    return builtin->get_builtin_type() == BuiltinType::character;
                default:
                    return false;
            }
        }

        // 对于指针类型，我们支持的唯一内置类型是字符串，
        // 确保DWARF指针类型指向字符类型，并且内置类型是字符串
        if (tag == DW_TAG_pointer_type) {
            return die[DW_AT_type].as_type().is_char_type() &&
                builtin->get_builtin_type() == BuiltinType::string;
        }
        return false;
    }

    // 两边都来自DIE.type
    // 此处似乎存在问题，对于char*和char, 去掉指针后是一致的，但他们是两种不同的类型，需要测试
    auto lhs_stripped = strip_all();
    auto rhs_stripped = rhs.strip_all();
    auto lhs_name = lhs_stripped.get_die().name();
    auto rhs_name = rhs_stripped.get_die().name();
    if (lhs_name && rhs_name && *lhs_name == *rhs_name) {
        return true;
    }

    return false;
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

std::size_t zdb::Type::alignment() const {
    if (!is_from_dwarf()) {
        return byte_size();
    }

    if (is_class_type()) {
        std::size_t max_alignment = 0;
        for (auto child : get_die().children()) {
            if (child.abbrev_entry()->tag == DW_TAG_member
                && (child.contains(DW_AT_data_member_location)
                || child.contains(DW_AT_data_bit_offset))
            ) {
                zdb::Type member_type = child[DW_AT_type].as_type();
                if (member_type.alignment() > max_alignment) {
                    max_alignment = member_type.alignment();
                }
            }
        }
        return max_alignment;
    }

    if (get_die().abbrev_entry()->tag == DW_TAG_array_type) {
        return get_die()[DW_AT_type].as_type().alignment();
    }
    
    return byte_size();
}

// 检查参数是否有未对齐的字段
bool zdb::Type::has_unaligned_fields() const {
    if (!is_from_dwarf()) {
        return false;
    }

    if (is_class_type()) {
        for (auto child : get_die().children()) {
            if (child.abbrev_entry()->tag == DW_TAG_member
                && child.contains(DW_AT_data_member_location)
            ) {
                auto member_type = child[DW_AT_type].as_type();
                if (child[DW_AT_data_member_location].as_int()
                    % member_type.alignment() != 0) {
                    return true;
                }
                if (member_type.has_unaligned_fields()) {
                    return true;
                }
            }
        }
    }

    return false;
}

// 检查参数是否为NTFPOC. 对于NTFPOC类型，只支持指针传递
// NTFPOC定义详见docs/NTFPOC.md
bool zdb::Type::is_non_trivial_for_calls() const {
    auto stripped = strip_cv_typedef().get_die();
    auto tag = stripped.abbrev_entry()->tag;

    if (tag == DW_TAG_array_type) {
        return stripped[DW_AT_type].as_type().is_non_trivial_for_calls();
    }

    if (tag != DW_TAG_class_type
        && tag != DW_TAG_structure_type
        && tag != DW_TAG_union_type
    ) {
        return false;
    }

    for (auto& child : stripped.children()) {

        // 非静态成员字段成员变量是否是NTFPOC
        if (child.abbrev_entry()->tag == DW_TAG_member
            && (child.contains(DW_AT_data_member_location)
            || child.contains(DW_AT_data_bit_offset))
        ) {
            if (child[DW_AT_type].as_type().is_non_trivial_for_calls()) {
                return true;
            }
        }

        // 基类继承是否是
        if (child.abbrev_entry()->tag == DW_TAG_inheritance) {
            if (child[DW_AT_type].as_type().is_non_trivial_for_calls()) {
                return true;
            }
        }

        // 存在虚函数
        if (child.contains(DW_AT_virtuality) 
            && child[DW_AT_virtuality].as_int() != DW_VIRTUALITY_none
        ) {
            return true;
        }
        
        
        if (child.abbrev_entry()->tag == DW_TAG_subprogram 
        ) { 
            // 构造函数不是默认的
            if (is_copy_or_move_constructor(*this, child)
                && (!child.contains(DW_AT_defaulted)
                || !child[DW_AT_defaulted].as_int() != DW_DEFAULTED_in_class)
            ) {
                return true;
            }
            else if (is_destructor(child)
                && (!child.contains(DW_AT_defaulted)
                || !child[DW_AT_defaulted].as_int() != DW_DEFAULTED_in_class)
            ) {

            }
        }
    }

    return false;
}

std::array<zdb::ParameterClass, 2> zdb::Type::get_parameter_classes() const {
    std::array<zdb::ParameterClass, 2> classes = {
        zdb::ParameterClass::no_class, 
        zdb::ParameterClass::no_class 
    };

    if (!is_from_dwarf()) {
        switch (get_builtin_type()) {
            case zdb::BuiltinType::boolean: 
            case zdb::BuiltinType::character: 
            case zdb::BuiltinType::integer: 
            case zdb::BuiltinType::string: 
                classes[0] = zdb::ParameterClass::integer; 
                break;
            case BuiltinType::floating_point: 
                classes[0] = zdb::ParameterClass::sse; break;
        }
        return classes;
    }

    auto stripped = strip_cv_typedef();
    auto die = stripped.get_die();
    auto tag = die.abbrev_entry()->tag;
    if (tag == DW_TAG_base_type && stripped.byte_size() <= 8) {
        switch (die[DW_AT_encoding].as_int()) {
        case DW_ATE_boolean:
        case DW_ATE_signed:
        case DW_ATE_signed_char:
        case DW_ATE_unsigned:
        case DW_ATE_unsigned_char: 
            classes[0] = ParameterClass::integer; break;
        case DW_ATE_float: 
            // 不支持m256之类
            classes[0] = ParameterClass::sse; break;
        default: 
            zdb::Error::send("Unimplemented base type encoding");
        }
    }
    else if (tag == DW_TAG_pointer_type 
        || tag == DW_TAG_reference_type 
        || tag == DW_TAG_rvalue_reference_type
    ) {
        classes[0] = ParameterClass::integer;
    }
    else if (tag == DW_TAG_base_type
        && die[DW_AT_encoding].as_int() == DW_ATE_float
        && stripped.byte_size() == 16
    ) {
        classes[0] = ParameterClass::x87;
        classes[1] = ParameterClass::x87up;
    }
    else if (tag == DW_TAG_class_type 
        || tag == DW_TAG_structure_type
        || tag == DW_TAG_union_type
        || tag == DW_TAG_array_type
    ) {
        classes = classify_class_type(*this);
    }
    return classes;
}