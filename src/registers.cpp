#include <libzdb/bit.hpp>
#include <libzdb/process.hpp>
#include <libzdb/registers.hpp>

zdb::Registers::Value zdb::Registers::read(const RegisterInfo &info) const {
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

void zdb::Registers::write(const RegisterInfo &info, Value val) {
    auto bytes = as_bytes(data_);
    std::visit(
        [&](auto &v) {
            if (sizeof(v) == info.size) {
                auto val_bytes = as_bytes(v);
                std::copy(val_bytes, val_bytes + sizeof(v), bytes + info.offset);
            } else {
                zdb::Error::send("Invalid value size");
            }
        },
        val
    );

    proc_->write_user_area(
        info.offset,
        from_bytes_as<std::uint64_t>(bytes + info.offset)
    );
}

