#ifndef LIBZDB_DWARF_HPP
#define LIBZDB_DWARF_HPP

#include <libzdb/detail/dwarf.h>

namespace zdb {
    class ELF;
    class Dwarf {
      public:
        Dwarf(const ELF &parent);
        const ELF* elf() const { return _elf; }

      private:
        const ELF *_elf;
    };
}

#endif
