#include "llvm/Transforms/Utils/SecretRegClass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicsRISCV.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"

using namespace llvm;

// Returns true if this instruction should be wrapped: it carries !secret,
// produces an integer SSA value, and is not already a mojov.secret call.
static bool needsSecretWrap(Instruction &I) {
    if (!I.getMetadata("secret"))       return false;
    if (I.getType()->isVoidTy())        return false;
    if (!I.getType()->isIntegerTy())    return false;
    if (I.isTerminator())               return false;

    // Don't double-wrap an existing @llvm.riscv.mojov.secret call.
    if (auto *CI = dyn_cast<CallInst>(&I))
        if (Function *F = CI->getCalledFunction())
            if (F->getIntrinsicID() == Intrinsic::riscv_mojov_secret)
                return false;

    return true;
}

PreservedAnalyses SecretRegClassPass::run(Module &M, ModuleAnalysisManager &AM) {
    bool Changed = false;

    for (Function &F : M) {
        if (F.isDeclaration()) continue;

        // Collect candidates first; we'll mutate the instruction list below.
        SmallVector<Instruction *, 16> ToWrap;
        for (BasicBlock &BB : F)
            for (Instruction &I : BB)
                if (needsSecretWrap(I))
                    ToWrap.push_back(&I);

        for (Instruction *I : ToWrap) {
            IntegerType *Ty = cast<IntegerType>(I->getType());
            Function *SecretFn = Intrinsic::getOrInsertDeclaration(
                &M, Intrinsic::riscv_mojov_secret, {Ty});

            // Insert the wrapper immediately after the tagged instruction.
            IRBuilder<> Builder(I->getNextNode());
            CallInst *Wrapper = Builder.CreateCall(SecretFn, {I},
                                                   I->getName() + ".secret");

            // All uses of the original value that follow the wrapper now use
            // the wrapper's result instead, ensuring they see a SecretGPR value.
            I->replaceUsesWithIf(Wrapper, [&](Use &U) {
                // Don't replace the use inside the wrapper itself.
                return U.getUser() != Wrapper;
            });

            Changed = true;
        }
    }

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
