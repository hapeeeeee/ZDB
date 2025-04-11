#ifndef LIBZDB_TYPES_HPP
#define LIBZDB_TYPES_HPP

#include <cstddef>
#include <array>
#include <cstdint>
#include <vector>
#include <cassert>

namespace zdb {
    using byte64 = std::array<std::byte, 8>;
    using byte128 = std::array<std::byte, 16>;


    // consider three different kinds of addresses: 
    // absolute offsets from the start of the object file (corresponding to the `zdb::FileOffset` type),
    // virtual addresses specified in the ELF file (corresponding to the `zdb::FileAddr` type), 
    // the actual virtual addresses in the executing program (corresponding to the `zdb::VirtAddr` type).
    class FileAddr;
    class ELF;
    class VirtualAddr {
        public:
            VirtualAddr() = default;
            explicit VirtualAddr(uint64_t addr) : addr_(addr) {}
            std::uint64_t addr() const { return addr_; }

            FileAddr to_file_addr(const ELF& elf) const;
            
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

    class FileOffset {
        public:
            FileOffset() = default;
            FileOffset(const ELF& elf, std::uint64_t offset): elf_(&elf), offset_(offset) {}
            std::uint64_t off() const {
                return offset_;
            }
            const ELF* elf_file() const {
                return elf_;
            }

        private:
            const ELF* elf_ = nullptr;
            std::uint64_t offset_ = 0;
    };

    class FileAddr {
        public:
            FileAddr() = default;
            FileAddr(const ELF& elf, std::uint64_t addr) : elf_(&elf), addr_(addr) {}

            std::uint64_t addr() const { return addr_; }
            const ELF* elf() const { return elf_; }

            VirtualAddr to_virt_addr() const;

            FileAddr operator+(std::int64_t offset) const {
                return FileAddr(*elf_, addr_ + offset);
            }

            FileAddr operator-(std::int64_t offset) const {
                return FileAddr(*elf_, addr_ - offset);
            }

            FileAddr& operator+=(std::int64_t offset) {
                addr_ += offset;
                return *this;
            }

            FileAddr& operator-=(std::int64_t offset) {
                addr_ -= offset;
                return *this;
            }

            bool operator==(const FileAddr& other) const {
                return addr_ == other.addr_ and elf_ == other.elf_;
            }

            bool operator!=(const FileAddr& other) const {
                return addr_ != other.addr_ or elf_ != other.elf_;
            }

            bool operator<(const FileAddr& other) const {
                assert(elf_ == other.elf_);
                return addr_ < other.addr_;
            }

            bool operator<=(const FileAddr& other) const {
                assert(elf_ == other.elf_);
                return addr_ <= other.addr_;
            }

            bool operator>(const FileAddr& other) const {
                assert(elf_ == other.elf_);
                return addr_ > other.addr_;
            }

            bool operator>=(const FileAddr& other) const {
                assert(elf_ == other.elf_);
                return addr_ >= other.addr_;
            }

        private:
            const ELF* elf_ = nullptr;
            std::uint64_t addr_;
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