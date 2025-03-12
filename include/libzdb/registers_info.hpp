#ifndef LIBZDB_REGISTERS_INFO_HPP
#define LIBZDB_REGISTERS_INFO_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <sys/user.h>
#include <libzdb/error.hpp>
#include <algorithm>
namespace zdb {

    enum class RegisterId {
        #define DEFINE_REGISTER(name, dwarf_id, size, offset, type, format) name
        #include <libzdb/detail/registers.inc>
        #undef DEFINE_REGISTER
    };

    enum class RegisterType {
        gpr,     ///<  general purpose register
        sub_gpr, ///< sub register of general purpose register
        fpr,     ///< floating point register
        dr       ///< double precision register
    };

    enum class RegisterFormat {
        uint,         ///< unsigned integer
        double_float, ///< double precision floating point
        long_double,  ///< long double precision floating point
        vector,       ///< vector
    };

    struct RegisterInfo {
        RegisterId id;
        std::string_view name;
        std::int32_t dwarf_id;
        std::size_t size;
        std::size_t offset;
        RegisterType type;
        RegisterFormat format;
    };

    inline constexpr const RegisterInfo g_register_infos[] = {
        #define DEFINE_REGISTER(name, dwarf_id, size, offset, type, format)                                                              \
            { RegisterId::name, #name, dwarf_id, size, offset, type, format }
        #include <libzdb/detail/registers.inc>
        #undef DEFINE_REGISTER
    };

    template <class F>
    const RegisterInfo& find_register_info_by(F f) {
        auto it = std::find_if(
            std::begin(g_register_infos), 
            std::end(g_register_infos), 
            f
        );
        if (it == std::end(g_register_infos)) {
            Error::send("Cannot find register info.");
        }
        return *it;
    }

    inline const RegisterInfo& find_register_info_by_id(RegisterId id) {
        return find_register_info_by(
            [id](const RegisterInfo& info) {return info.id == id;}
        );
    }

    inline const RegisterInfo& find_register_info_by_name(std::string_view name) {
        return find_register_info_by(
            [name](const RegisterInfo& info) {return info.name == name;}
        );
    }

    inline const RegisterInfo& find_register_info_by_dwarf_id(std::int32_t dwarf_id) {
        return find_register_info_by(
            [dwarf_id](const RegisterInfo& info) {return info.dwarf_id == dwarf_id;}
        );
    }
}
#endif // LIBZDB_REGISTERS_INFO_HPP
