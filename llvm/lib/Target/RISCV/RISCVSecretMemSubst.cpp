//===-- RISCVSecretMemSubst.cpp - Replace SD/LD with SDE/LDE for SecretGPR ===//
//
// Post-RA pass. After register allocation all physical registers are known.
// Any store whose source register (rs2) is in SecretGPR (x24-x31) must use
// SDE so the hardware encrypts the value on the way to memory. Any load whose
// destination register (rd) is in SecretGPR must use LDE so the hardware
// decrypts on the way in.
//
// All store widths (SB/SH/SW/SD) and load widths (LB/LH/LW/LD and unsigned
// variants) are replaced — SDE/LDE always operate on the full 64-bit register
// value; the caller is responsible for ensuring the target memory region is
// at least 16 bytes wide (fast format) so the 128-bit ciphertext fits.
//
//===----------------------------------------------------------------------===//

#include "RISCV.h"
#include "RISCVSubtarget.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

using namespace llvm;

#define DEBUG_TYPE "riscv-secret-mem-subst"
#define PASS_NAME "RISC-V Secret Memory Substitution (SD→SDE / LD→LDE)"

// Integer store opcodes whose source register (operand 0) must be checked.
static const unsigned StoreOpcodes[] = {
    RISCV::SB, RISCV::SH, RISCV::SW, RISCV::SD,
};

// Integer load opcodes whose destination register (operand 0) must be checked.
static const unsigned LoadOpcodes[] = {
    RISCV::LB, RISCV::LH, RISCV::LW, RISCV::LD,
    RISCV::LBU, RISCV::LHU, RISCV::LWU,
};

namespace {

class RISCVSecretMemSubstPass : public MachineFunctionPass {
public:
  static char ID;
  RISCVSecretMemSubstPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override;

  StringRef getPassName() const override { return PASS_NAME; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    MachineFunctionPass::getAnalysisUsage(AU);
  }
};

} // namespace

char RISCVSecretMemSubstPass::ID = 0;

INITIALIZE_PASS(RISCVSecretMemSubstPass, DEBUG_TYPE, PASS_NAME,
                /* cfgonly */ false, /* analysis */ false)

static bool isStore(unsigned Opc) {
  for (unsigned S : StoreOpcodes)
    if (S == Opc)
      return true;
  return false;
}

static bool isLoad(unsigned Opc) {
  for (unsigned L : LoadOpcodes)
    if (L == Opc)
      return true;
  return false;
}

bool RISCVSecretMemSubstPass::runOnMachineFunction(MachineFunction &MF) {
  const auto &STI = MF.getSubtarget<RISCVSubtarget>();
  const RISCVInstrInfo *TII = STI.getInstrInfo();

  bool Changed = false;

  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      unsigned Opc = MI.getOpcode();

      if (isStore(Opc)) {
        // Store format: rs2 (data, op0), rs1 (base, op1), imm12 (op2).
        Register DataReg = MI.getOperand(0).getReg();
        if (RISCV::SecretGPRRegClass.contains(DataReg)) {
          MI.setDesc(TII->get(RISCV::SDE));
          Changed = true;
        }
      } else if (isLoad(Opc)) {
        // Load format: rd (def, op0), rs1 (base, op1), imm12 (op2).
        Register DataReg = MI.getOperand(0).getReg();
        if (RISCV::SecretGPRRegClass.contains(DataReg)) {
          MI.setDesc(TII->get(RISCV::LDE));
          Changed = true;
        }
      }
    }
  }

  return Changed;
}

FunctionPass *llvm::createRISCVSecretMemSubstPass() {
  return new RISCVSecretMemSubstPass();
}
