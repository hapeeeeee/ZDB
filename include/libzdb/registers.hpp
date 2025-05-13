#ifndef LIBZDB_REGISTERS_HPP
#define LIBZDB_REGISTERS_HPP

#include <libzdb/registers_info.hpp>
#include <libzdb/types.hpp>
#include <sys/user.h>
#include <variant>

namespace zdb {
    class Process;
    class Registers {
      public:
        using Value = std::variant<
            std::uint8_t,
            std::uint16_t,
            std::uint32_t,
            std::uint64_t,
            std::int8_t,
            std::int16_t,
            std::int32_t,
            std::int64_t,
            float,
            double,
            long double,
            byte64,
            byte128
        >;

      public:
        Registers()                             = default;
        Registers(const Registers &)            = default;
        Registers &operator=(const Registers &) = default;

        Value read(const RegisterInfo &info) const;
        void write(const RegisterInfo &info, Value val, bool commit=true);

        template <class T> 
        T read_by_id_as(RegisterId id) const {
            return std::get<T>(read(find_register_info_by_id(id)));
        }

        template <class T> 
        T read_by_name_as(std::string_view name) const {
            return std::get<T>(read(find_register_info_by_name(name)));
        }

        void write_by_id(RegisterId id, Value val, bool commit=true) {
            write(find_register_info_by_id(id), val, commit);
        }

        void write_by_name(std::string_view name, Value val, bool commit=true) {
            write(find_register_info_by_name(name), val, commit);
        }

        bool is_undefined(RegisterId id) const;
        void undefine(RegisterId id);
        VirtualAddr cfa() const { return cfa_; }
        void set_cfa(VirtualAddr addr) { cfa_ = addr; }
        void flush();

      private:
        friend Process;
        Registers(Process &proc) : proc_(&proc) {}

        zdb::Process *proc_;
        user data_;
        std::vector<std::size_t> undefineds_;
        VirtualAddr cfa_;
    };
} // namespace zdb

#endif // LIBZDB_REGISTERS_HPP
