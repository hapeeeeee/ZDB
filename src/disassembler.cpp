#include <Zydis/Zydis.h>
#include <libzdb/disassembler.hpp>

std::vector<zdb::Disassembler::Instruction> zdb::Disassembler::disassemble(
    std::size_t n_instructions, 
    std::optional<VirtualAddr> address
) {
    std::vector<Instruction> result;
    result.reserve(n_instructions);

    if (!address) {
        address.emplace(proc_.get_pc());
    }
    auto code = proc_.read_memory_without_trap(address.value(), n_instructions * 15);

    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instr;

    while (
        ZYAN_SUCCESS(
            ZydisDisassembleATT(
                ZYDIS_MACHINE_MODE_LONG_64, 
                address->addr(),
                code.data() + offset, 
                code.size() - offset,
                &instr
            )
        ) 
        && n_instructions > 0
    ) {
        result.push_back(Instruction{
            .address = address.value(),
            .text = std::string(instr.text),
        });
        offset += instr.info.length;
        *address += instr.info.length;
        --n_instructions;
    }
    return result;
}