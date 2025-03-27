#include <libzdb/syscall.hpp>
#include <libzdb/error.hpp>
#include <unordered_map>

namespace {
    const std::unordered_map<std::string_view, int> g_syscall_name_map = {
        #define DEFINE_SYSCALL(name,id) { #name, id },
        #include "syscall.inc"
        #undef DEFINE_SYSCALL
    };
}

namespace zdb {
    std::string_view syscall_id_to_name(int id) {
        switch (id) {
            #define DEFINE_SYSCALL(name, id) case id: return #name;
            #include "syscall.inc"
            #undef DEFINE_SYSCALL
        default: Error::send("No such syscall");
        }
    }

    int syscall_name_to_id(std::string_view name) {
        if (g_syscall_name_map.count(name) != 1) {
            Error::send("No such syscall");
        }
        return g_syscall_name_map.at(name);
    }
};