#ifndef LIBZDB_TYPES_HPP
#define LIBZDB_TYPES_HPP

#include <cstddef>
#include <array>
#include <cstdint>

namespace zdb {
    using byte64 = std::array<std::byte, 8>;
    using byte128 = std::array<std::byte, 16>;

    class VirtualAddr {
        public:
            VirtualAddr() = default;
            explicit VirtualAddr(uint64_t addr) : addr_(addr) {}
            std::uint64_t addr() const { return addr_; }
            
            VirtualAddr operator+(std::int64_t offset) const {
                return VirtualAddr(addr_ + offset);
            }
            VirtualAddr operator-(std::int64_t offset) const {
                return VirtualAddr(addr_ - offset);
            }
            VirtualAddr& operator+=(std::int64_t offset) {
                addr_ += offset;
                return *this;
            }
            VirtualAddr& operator-=(std::int64_t offset) {
                addr_ -= offset;
                return *this;
            }
            bool operator==(const VirtualAddr& other) const {
                return addr_ == other.addr_;
            }
            bool operator!=(const VirtualAddr& other) const {
                return addr_ != other.addr_;
            }
            bool operator<(const VirtualAddr& other) const {
                return addr_ < other.addr_;
            }
            bool operator<=(const VirtualAddr& other) const {
                return addr_ <= other.addr_;
            }
            bool operator>(const VirtualAddr& other) const {
                return addr_ > other.addr_;
            }
            bool operator>=(const VirtualAddr& other) const {
                return addr_ >= other.addr_;
            }

        private:
            uint64_t addr_;
    };
    
}
#endif // LIBZDB_TYPES_HPP