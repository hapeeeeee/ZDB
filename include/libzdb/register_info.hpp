#ifndef LIBZDB_REGISTER_INFO_HPP
#define LIBZDB_REGISTER_INFO_HPP

#include <string_view>
#include <sys/user.h>
#include <cstdint>
#include <cstddef>

namespace zdb {

    enum class RegisterId {
        #define DEFINE_REGISTER(name,dwarf_id,size,offset,type,format) name
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
        #define DEFINE_REGISTER(name,dwarf_id,size,offset,type,format) \
            { RegisterId::name, #name, dwarf_id, size, offset, type, format }
        #include <libzdb/detail/registers.inc>
        #undef DEFINE_REGISTER
    };
} // namespace zdb
#endif // LIBZDB_REGISTER_INFO_HPP
