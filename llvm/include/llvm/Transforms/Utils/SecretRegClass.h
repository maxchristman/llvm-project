#ifndef LLVM_TRANSFORMS_UTILS_SECRETREGCLASS_H
#define LLVM_TRANSFORMS_UTILS_SECRETREGCLASS_H

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

// Wraps every !secret-tagged integer value-producing instruction with a call
// to @llvm.riscv.mojov.secret.*, signalling to the RISC-V backend that the
// result must be allocated in SecretGPR (x24-x31).
class SecretRegClassPass : public PassInfoMixin<SecretRegClassPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

#endif
