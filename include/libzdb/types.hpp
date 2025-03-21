#ifndef LIBZDB_TYPES_HPP
#define LIBZDB_TYPES_HPP

#include <cstddef>
#include <array>
#include <cstdint>
#include <vector>

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
    
    template<class T>
    class Span {
      public:
        Span() = default;
        Span(T* data, std::size_t size): data_(data), size_(size) {}
        Span(T* data, T* end): data_(data), size_(end - data) {}
        template<class U>
        Span(const std::vector<U>& vec): data_(vec.data()), size_(vec.size()) {}

        T* begin() const { return data_; }
        T* end() const { return data_ + size_; }
        T& operator[](std::size_t index) const { return *(data_ + index); }
        std::size_t size() const { return size_; }

      private:
        T* data_ = nullptr;
        std::size_t size_ = 0;
    };

    enum class StopPointMode {
        Write,
        ReadWrite,
        Execute,
    };
}
#endif // LIBZDB_TYPES_HPP