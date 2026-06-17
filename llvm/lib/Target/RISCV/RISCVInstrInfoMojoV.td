//===-- RISCVInstrInfoMojoV.td - Mojo-V instructions --------*- tablegen -*-===//
//
// Mojo-V encrypted load/store. Both use CUSTOM-0 opcode (0x0b).
// The hardware enforces that the data register (rd/rs2) is in x24-x31;
// any other register causes a trap_security_exception in Spike.
//
// Memory format (FAST mode, 128 bits):
//   SDE rs2, offset(rs1)  →  writes 16 bytes: encrypt({rs2_val, salt, sig})
//   LDE rd, offset(rs1)   →  reads 16 bytes:  rd ← decrypt(mem[rs1+offset]).val
//
//===----------------------------------------------------------------------===//

// LDE — encrypted load: lde rd, offset(rs1)
// I-type, CUSTOM-0, funct3=0x0
let hasSideEffects = 0, mayLoad = 1, mayStore = 0 in
def LDE : RVInstI<0b000, OPC_CUSTOM_0,
                  (outs SecretGPR:$rd),
                  (ins GPRMem:$rs1, simm12_lo:$imm12),
                  "lde", "$rd, ${imm12}(${rs1})">;

// SDE — encrypted store: sde rs2, offset(rs1)
// S-type, CUSTOM-0, funct3=0x1
let hasSideEffects = 0, mayLoad = 0, mayStore = 1 in
def SDE : RVInstS<0b001, OPC_CUSTOM_0,
                  (outs),
                  (ins SecretGPR:$rs2, GPRMem:$rs1, simm12_lo:$imm12),
                  "sde", "$rs2, ${imm12}(${rs1})">;
