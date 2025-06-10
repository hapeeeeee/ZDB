#include <libzdb/bit.hpp>
#include <libzdb/process.hpp>
#include <libzdb/registers.hpp>

#include <type_traits>
#include <algorithm>
namespace {
    template <class T>
    zdb::byte128 widen(const zdb::RegisterInfo& info, T t) {
        using namespace zdb;
        if constexpr (std::is_floating_point_v<T>) {
            if (info.format == RegisterFormat::double_float)
                return as_byte128(static_cast<double>(t));
            if (info.format == RegisterFormat::long_double)
                return as_byte128(static_cast<long double>(t));
        }
        else if constexpr (std::is_signed_v<T>) {
            if (info.format == RegisterFormat::uint) {
                switch (info.size) {
                    case 2: return as_byte128(static_cast<std::int16_t>(t));
                    case 4: return as_byte128(static_cast<std::int32_t>(t));
                    case 8: return as_byte128(static_cast<std::int64_t>(t));
                }
            }
        }
        return as_byte128(t);
    }
}


zdb::Registers::Value zdb::Registers::read(const RegisterInfo &info) const {
    if (is_undefined(info.id))
        zdb::Error::send("Register is undefined");

    auto bytes = as_bytes(data_);
    if (info.format == RegisterFormat::uint) {
        switch (info.size) {
        case 1:
            return from_bytes_as<std::uint8_t>(bytes + info.offset);
        case 2:
            return from_bytes_as<std::uint16_t>(bytes + info.offset);
        case 4:
            return from_bytes_as<std::uint32_t>(bytes + info.offset);
        case 8:
            return from_bytes_as<std::uint64_t>(bytes + info.offset);
        default:
            zdb::Error::send("Unsupported register size");
        }
    } else if (info.format == RegisterFormat::double_float) {
        return from_bytes_as<double>(bytes + info.offset);
    } else if (info.format == RegisterFormat::long_double) {
        return from_bytes_as<long double>(bytes + info.offset);
    } else if (info.format == RegisterFormat::vector && info.size == 8) {
        return from_bytes_as<byte64>(bytes + info.offset);
    } else if (info.format == RegisterFormat::vector && info.size == 16) {
        return from_bytes_as<byte128>(bytes + info.offset);
    } else {
        zdb::Error::send("Unsupported register format");
    }
}

void zdb::Registers::write(const RegisterInfo &info, Value val, bool commit) {
    auto bytes = as_bytes(data_);
    std::visit(
        [&](auto &v) {
            if (sizeof(v) <= info.size) {
                auto widen_v = widen(info, v);
                auto val_bytes = as_bytes(widen_v);
                std::copy(val_bytes, val_bytes + info.size, bytes + info.offset);
            } else {
                zdb::Error::send("Invalid value size");
            }
        },
        val
    );

    if (commit) {
        if (info.type == RegisterType::fpr) {
            proc_->write_fprs(data_.i387, tid_);
        } else {
            auto aligned_offset = info.offset & ~0b111;
            proc_->write_user_area(
                aligned_offset,
                from_bytes_as<std::uint64_t>(bytes + aligned_offset),
                tid_
            );
        }
    }
}
    
void zdb::Registers::undefine(RegisterId id) {
    std::size_t canonical_offset = find_register_info_by_id(id).offset >> 1;
    undefineds_.push_back(canonical_offset);
}

bool zdb::Registers::is_undefined(RegisterId id) const {
    std::size_t canonical_offset = find_register_info_by_id(id).offset >> 1;
    return std::find(
        begin(undefineds_), 
        end(undefineds_), 
        canonical_offset
    ) != end(undefineds_);
}

void zdb::Registers::flush() {
    proc_->write_fprs(data_.i387, tid_);
    proc_->write_gprs(data_.regs, tid_);
    auto info = find_register_info_by_id(RegisterId::dr0);
    for (auto i = 0; i < 8; ++i) {
        if (i == 4 or i == 5) continue;
        auto reg_offset = info.offset + sizeof(std::uint64_t) * i;
        auto ptr = reinterpret_cast<std::byte*>(data_.u_debugreg + i);
        auto bytes = from_bytes_as<std::uint64_t>(ptr);
        proc_->write_user_area(reg_offset, bytes, tid_);
    }
}