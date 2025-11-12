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

    inline void memcpy_bits(
        std::uint8_t* dest, 
        std::uint32_t dest_bit,
        const std::uint8_t* src, 
        std::uint32_t src_bit,
        std::uint32_t n_bits
    ) {
        for (; n_bits; --n_bits, ++src_bit, ++dest_bit) {
            std::uint8_t dest_mask = 1 << (dest_bit % 8);
            dest[dest_bit / 8] &= ~dest_mask;
            auto src_mask = 1 << (src_bit % 8);
            auto corresponding_src_bit_set = src[src_bit / 8] & src_mask;
            if (corresponding_src_bit_set) {
                dest[dest_bit / 8] |= dest_mask;
            }
        }
    }

    template<class From>
    zdb::Span<const std::byte> to_byte_span(const From& from) {
        return { as_bytes(from), sizeof(From) };
    }

    template<class From>
    std::vector<std::byte> to_byte_vec(const From& from) {
        std::vector<std::byte> ret(sizeof(From));
        std::memcpy(ret.data(), as_bytes(from), sizeof(From));
        return ret;
    }
}
#endif // LIBZDB_BIT_HPP