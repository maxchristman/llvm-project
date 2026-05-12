//===-- RISCVSecretConstraint.cpp - Propagate SecretGPR register class ----===//
//
// Mojo-V hardware rule: any instruction that reads from a secret register
// (x16-x31) must also write its result to a secret register.  Placing a
// secret-derived value in a public register is a hardware fault.
//
// The SecretRegClass IR pass inserts @llvm.riscv.mojov.secret intrinsics which
// become COPY_TO_REGCLASS nodes in MachineIR, constraining the *intrinsic's*
// result to SecretGPR.  But the arithmetic instruction that feeds the intrinsic
// still writes to a plain GPR virtual register, violating the rule.
//
// This pre-RA pass walks every MachineInstr and, for any instruction that
// reads from a SecretGPR-class virtual register, constrains all of its def
// virtual registers to SecretGPR as well.  A single forward fixed-point
// iteration is sufficient because register class info propagates in def→use
// order within a function.
//
//===----------------------------------------------------------------------===//

#include "RISCV.h"
#include "RISCVRegisterInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"

using namespace llvm;

#define DEBUG_TYPE "riscv-secret-constraint"
#define PASS_NAME "RISC-V Secret Register Constraint Propagation"

namespace {

class RISCVSecretConstraintPass : public MachineFunctionPass {
public:
  static char ID;
  RISCVSecretConstraintPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override;

  StringRef getPassName() const override { return PASS_NAME; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
    MachineFunctionPass::getAnalysisUsage(AU);
  }
};

} // namespace

char RISCVSecretConstraintPass::ID = 0;

INITIALIZE_PASS(RISCVSecretConstraintPass, DEBUG_TYPE, PASS_NAME,
                /* cfgonly */ false, /* analysis */ false)

bool RISCVSecretConstraintPass::runOnMachineFunction(MachineFunction &MF) {
  MachineRegisterInfo &MRI = MF.getRegInfo();
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  const TargetRegisterClass *SecretRC = &RISCV::SecretGPRRegClass;

  bool Changed = false;

  // Single forward pass; iterate until stable to handle multi-BB chains.
  bool AnyChange = true;
  while (AnyChange) {
    AnyChange = false;
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        // Skip pure copies between register classes — they are the mechanism
        // that intentionally moves a value between domains.  The only
        // legitimate secret→public copy is one we emit ourselves; any
        // unintended ones will be caught when the instruction that produced
        // the secret-class source is fixed up in a later iteration.
        if (MI.isCopy() || MI.isImplicitDef() || MI.isPHI())
          continue;

        // Check whether any USE operand's virtual register is in SecretGPR.
        bool HasSecretSrc = false;
        for (const MachineOperand &MO : MI.uses()) {
          if (!MO.isReg() || !MO.getReg().isVirtual())
            continue;
          if (MRI.getRegClass(MO.getReg()) == SecretRC) {
            HasSecretSrc = true;
            break;
          }
        }
        if (!HasSecretSrc)
          continue;

        // For each DEF virtual register that is NOT already SecretGPR,
        // tighten its register class to the common sub-class of its current
        // class and SecretGPR.  If the classes are disjoint (e.g., a
        // floating-point def), getCommonSubClass returns null and we leave
        // it alone.
        for (MachineOperand &MO : MI.defs()) {
          if (!MO.isReg() || !MO.getReg().isVirtual())
            continue;
          Register Reg = MO.getReg();
          const TargetRegisterClass *OldRC = MRI.getRegClass(Reg);
          if (OldRC == SecretRC)
            continue;
          const TargetRegisterClass *NewRC =
              TRI->getCommonSubClass(OldRC, SecretRC);
          if (!NewRC)
            continue;
          MRI.setRegClass(Reg, NewRC);
          AnyChange = true;
          Changed = true;
        }
      }
    }
  }

  return Changed;
}

FunctionPass *llvm::createRISCVSecretConstraintPass() {
  return new RISCVSecretConstraintPass();
}
