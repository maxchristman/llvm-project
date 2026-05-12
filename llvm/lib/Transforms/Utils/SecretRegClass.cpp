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
            IntegerType *OrigTy = cast<IntegerType>(I->getType());

            // Mojo-V targets RV64: the only legal integer type for SecretGPR is
            // i64. Promote any narrower value (i1/i8/i16/i32) to i64 before
            // wrapping so the RISC-V type legalizer always sees a legal type.
            unsigned WrapWidth = OrigTy->getBitWidth() < 64
                                     ? 64u
                                     : OrigTy->getBitWidth();
            IntegerType *WrapTy = IntegerType::get(M.getContext(), WrapWidth);

            Function *SecretFn = Intrinsic::getOrInsertDeclaration(
                &M, Intrinsic::riscv_mojov_secret, {WrapTy});

            // Insert the promotion chain immediately after the tagged instruction.
            IRBuilder<> Builder(I->getNextNode());

            Value *Input = (WrapTy != OrigTy)
                ? Builder.CreateZExt(I, WrapTy, I->getName() + ".zext")
                : static_cast<Value *>(I);

            CallInst *Wrapper = Builder.CreateCall(SecretFn, {Input},
                                                   I->getName() + ".secret");

            Value *Result = (WrapTy != OrigTy)
                ? Builder.CreateTrunc(Wrapper, OrigTy, I->getName() + ".trunc")
                : static_cast<Value *>(Wrapper);

            // Replace all subsequent uses with Result, preserving the uses
            // inside the promotion chain itself (zext and wrapper).
            I->replaceUsesWithIf(Result, [&](Use &U) {
                return U.getUser() != Input && U.getUser() != Wrapper;
            });

            Changed = true;
        }
    }

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
