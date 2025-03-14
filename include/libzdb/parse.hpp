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

    template <class F>
    std::optional<F> to_float(std::string_view sv) {
        F ret;
        auto result = std::from_chars(sv.begin(), sv.end(), ret);
        if (result.ptr != sv.end()) {
            return std::nullopt;
        }
        return ret;
    }
}
#endif // ZDB_PARSE_HPP