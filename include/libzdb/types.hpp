#ifndef LIBZDB_TYPES_HPP
#define LIBZDB_TYPES_HPP

#include <cstddef>
#include <array>

namespace zdb {
    using byte64 = std::array<std::byte, 8>;
    using byte128 = std::array<std::byte, 16>;
}
#endif // LIBZDB_TYPES_HPP