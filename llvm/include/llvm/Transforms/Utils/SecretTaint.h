#ifndef LLVM_TRANSFORMS_UTILS_SECRETTAINT_H
#define LLVM_TRANSFORMS_UTILS_SECRETTAINT_H

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

class SecretTaintPass : public PassInfoMixin<SecretTaintPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

#endif
