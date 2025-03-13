#ifndef LIBZDB_BIT_HPP
#define LIBZDB_BIT_HPP

#include <cstring>
#include <libzdb/types.hpp>
#include <cstdint>
#include <vector>
#include <string_view>
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
    byte64 as_byte64(const From& from) {
        byte64 obj{};
        std::memcpy(&obj, &from, sizeof(From));
        return obj;
    }

    template<typename From>
    byte128 as_byte128(const From& from) {
        byte128 obj{};
        std::memcpy(&obj, &from, sizeof(From));
        return obj;
    }

    inline std::string_view to_string_view(const std::byte* bytes, std::size_t size) {
        return std::string_view(reinterpret_cast<const char*>(bytes), size);
    }

    inline std::string_view to_string_view(const std::vector<std::byte>& bytes) {
        return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
}
#endif // LIBZDB_BIT_HPP