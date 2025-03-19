#ifndef ZDB_PARSE_HPP
#define ZDB_PARSE_HPP

#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>

namespace zdb {

     template <class I>
    std::optional<I> to_integral(std::string_view sv, int base = 10) {
        auto begin = sv.begin();
        if (base == 16
            && sv.size() > 1
            && begin[0] == '0'
            && begin[1] == 'x'
        ) {
            begin += 2;
        }

        I ret;
        auto result = std::from_chars(begin, sv.end(), ret, base);
        if (result.ptr != sv.end()) {
            return std::nullopt;
        }
        return ret;
    }

    template<>
    inline std::optional<std::byte> to_integral(std::string_view sv, int base) {
        auto uint8 = to_integral<std::uint8_t>(sv, base);
        if (uint8) return static_cast<std::byte>(*uint8);
        return std::nullopt;
    }
   
    template <class F>
    std::optional<F> to_float(std::string_view sv) {
        F ret;
        auto result = std::from_chars(sv.begin(), sv.end(), ret);
        if (result.ptr != sv.end()) {
            return std::nullopt;
        }
        return ret;
    }

    /// @brief parse a vector from a string, like "[0x00,0x01,0x02]"
    template <std::size_t N>
    std::optional<std::array<std::byte, N>> parse_vector(std::string_view sv) {
        const char *ch = sv.data();
        if (*ch++ != '[') {
            zdb::Error::send("Invalid vector format");
        }

        std::array<std::byte, N> ret;
        for (std::size_t i = 0; i < N - 1; i++) {
            ret[i] = to_integral<std::byte>({ch, 4}, 16).value();
            ch += 4;
            if (*ch++ != ',') {
                zdb::Error::send("Invalid vector format");
            }
        }
        ret[N - 1] = to_integral<std::byte>({ch, 4}, 16).value();
        ch += 4;
        if (*ch++ != ']' || ch != sv.end()) {
            zdb::Error::send("Invalid vector format");
        }
        return ret;
    }

    inline std::vector<std::byte> parse_vector(std::string_view text) {
        std::vector<std::byte> bytes;
        const char* c = text.data();
        if (*c++ != '[') {
            zdb::Error::send("Invalid format");
        };
        while (*c != ']') {
            auto byte = zdb::to_integral<std::byte>({ c, 4 }, 16);
            bytes.push_back(byte.value());
            c += 4;
            if (*c == ',') ++c;
            else if (*c != ']') {
                zdb::Error::send("Invalid format");
            };
        }
        if (++c != text.end()) {
            zdb::Error::send("Invalid format");
        };
        return bytes;
    }
}
#endif // ZDB_PARSE_HPP