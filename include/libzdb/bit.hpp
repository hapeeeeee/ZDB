#ifndef LIBZDB_BIT_HPP
#define LIBZDB_BIT_HPP

#include <cstring>
#include <libzdb/types.hpp>
#include <cstdint>

namespace zdb {
    template<typename To>
    To from_bytes_as(const std::byte* bytes) {
        To obj;
        std::memcpy(&obj, bytes, sizeof(To));
        return obj;
    }

    template<typename From>
    std::byte* as_bytes(From& from) {
        return reinterpret_cast<std::byte*>(&from);
    }

    template<typename From>
    const std::byte* as_bytes(const From& from) {
        return reinterpret_cast<const std::byte*>(&from);
    }

    template<typename From>
    byte64 as_byte64(From& from) {
        byte64 obj{};
        std::memcpy(&obj, &from, sizeof(From));
        return obj;
    }

    template<typename From>
    byte128 as_byte128(From& from) {
        byte128 obj{};
        std::memcpy(&obj, &from, sizeof(From));
        return obj;
    }

        
}
#endif // LIBZDB_BIT_HPP