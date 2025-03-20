#ifndef LIBZDB_DISASSEMBLER_HPP
#define LIBZDB_DISASSEMBLER_HPP

#include <libzdb/process.hpp>
#include <optional>

namespace zdb {
    class Disassembler {
      public:
        struct Instruction {
            VirtualAddr address;
            std::string text;
        };

        Disassembler(Process& proc): proc_(proc) {} 
        std::vector<Instruction> disassemble(
            std::size_t n_instructions, 
            std::optional<VirtualAddr> address = std::nullopt);

      
      private:
        Process& proc_;
    };
}

#endif // LIBZDB_DISASSEMBLER_HPP