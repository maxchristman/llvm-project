#include "llvm/Transforms/Utils/SecretBranchElim.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// Returns true if V is an Instruction carrying !secret metadata.
static bool isSecretValue(Value *V) {
    if (auto *I = dyn_cast<Instruction>(V))
        return I->getMetadata("secret") != nullptr;
    return false;
}

// A branch is a secret branch if the taint pass tagged it with !secret.
static bool isSecretBranch(CondBrInst *BI) {
    return BI->getMetadata("secret") != nullptr;
}

// Verify the diamond shape:
//   - TrueBB and FalseBB each have exactly one predecessor (the header)
//   - Both end with an unconditional branch to the same MergeBB
//   - MergeBB has exactly two predecessors (TrueBB and FalseBB)
static bool checkDiamond(CondBrInst *BI,
                          BasicBlock *&TrueBB,
                          BasicBlock *&FalseBB,
                          BasicBlock *&MergeBB) {
    TrueBB  = BI->getSuccessor(0);
    FalseBB = BI->getSuccessor(1);

    if (!TrueBB->hasNPredecessors(1) || !FalseBB->hasNPredecessors(1))
        return false;

    auto *TrueTerm  = dyn_cast<UncondBrInst>(TrueBB->getTerminator());
    auto *FalseTerm = dyn_cast<UncondBrInst>(FalseBB->getTerminator());
    if (!TrueTerm || !FalseTerm) return false;

    MergeBB = TrueTerm->getSuccessor(0);
    if (FalseTerm->getSuccessor(0) != MergeBB) return false;

    // Exactly two predecessors guarantees phi nodes only reference TrueBB/FalseBB.
    if (!MergeBB->hasNPredecessors(2)) return false;

    return true;
}

// All non-terminator instructions in BB must be safe to execute speculatively
// (no stores, calls with side effects, potentially-trapping operations, etc.).
static bool checkSpeculatable(BasicBlock *BB) {
    for (Instruction &I : *BB) {
        if (I.isTerminator()) continue;
        if (!isSafeToSpeculativelyExecute(&I)) return false;
    }
    return true;
}

static void reportMemoryError(Instruction *I, Function &F) {
    std::string Msg;
    raw_string_ostream OS(Msg);
    OS << "secret-dependent memory address in '" << F.getName()
       << "' leaks via cache timing";
    if (DebugLoc DL = I->getDebugLoc())
        OS << " (" << DL->getFilename() << ":" << DL->getLine() << ")";
    F.getContext().emitError(Msg);
}

static void reportIndirectControlFlowError(Instruction *I, Function &F) {
    std::string Msg;
    raw_string_ostream OS(Msg);
    OS << "secret-dependent indirect control flow in '" << F.getName()
       << "' is not transformable";
    if (DebugLoc DL = I->getDebugLoc())
        OS << " (" << DL->getFilename() << ":" << DL->getLine() << ")";
    F.getContext().emitError(Msg);
}

static void reportError(CondBrInst *BI, Function &F) {
    std::string Msg;
    raw_string_ostream OS(Msg);
    OS << "secret-dependent branch in '" << F.getName()
       << "' cannot be converted to select";
    if (DebugLoc DL = BI->getDebugLoc())
        OS << " (" << DL->getFilename() << ":" << DL->getLine() << ")";
    F.getContext().emitError(Msg);
}

// Pre-condition: diamond shape and speculatability have been verified.
//
// Moves all non-terminator instructions from TrueBB and FalseBB into the
// header block, replaces each phi in MergeBB with a select, then rewires
// the header to branch unconditionally to MergeBB.
static void convertToSelect(CondBrInst *BI,
                             BasicBlock *TrueBB,
                             BasicBlock *FalseBB,
                             BasicBlock *MergeBB) {
    Value *Cond = BI->getCondition();
    BasicBlock::iterator InsertPt = BI->getIterator();

    // Collect instructions before moving (can't iterate while mutating).
    SmallVector<Instruction *, 8> TrueInsts, FalseInsts;
    for (Instruction &I : *TrueBB)
        if (!I.isTerminator()) TrueInsts.push_back(&I);
    for (Instruction &I : *FalseBB)
        if (!I.isTerminator()) FalseInsts.push_back(&I);

    // Speculate both sides into the header. Order within each side is
    // preserved so intra-block def-use chains remain valid.
    for (Instruction *I : TrueInsts)  I->moveBefore(InsertPt);
    for (Instruction *I : FalseInsts) I->moveBefore(InsertPt);

    // Replace each phi with a select using the original secret condition.
    IRBuilder<> Builder(BI);
    SmallVector<PHINode *, 4> PhisToErase;
    for (PHINode &Phi : MergeBB->phis()) {
        Value *TrueVal  = Phi.getIncomingValueForBlock(TrueBB);
        Value *FalseVal = Phi.getIncomingValueForBlock(FalseBB);
        Value *Sel = Builder.CreateSelect(Cond, TrueVal, FalseVal,
                                          Phi.getName() + ".sel");
        Phi.replaceAllUsesWith(Sel);
        PhisToErase.push_back(&Phi);
    }
    for (PHINode *Phi : PhisToErase)
        Phi->eraseFromParent();

    // Rewire header to jump directly to merge.
    Builder.CreateBr(MergeBB);
    BI->eraseFromParent();

    // Side blocks are now empty and unreachable; remove them.
    TrueBB->getTerminator()->eraseFromParent();
    FalseBB->getTerminator()->eraseFromParent();
    TrueBB->eraseFromParent();
    FalseBB->eraseFromParent();
}

static void checkSecretMemoryAccesses(Function &F) {
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (auto *LI = dyn_cast<LoadInst>(&I)) {
                if (isSecretValue(LI->getPointerOperand()))
                    reportMemoryError(LI, F);
            } else if (auto *SI = dyn_cast<StoreInst>(&I)) {
                if (isSecretValue(SI->getPointerOperand()))
                    reportMemoryError(SI, F);
            }
            // AtomicRMWInst/AtomicCmpXchgInst also have getPointerOperand()
            // but are out of scope for this initial implementation.
        }
    }
}

static void checkSecretIndirectControlFlow(Function &F) {
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (auto *IBI = dyn_cast<IndirectBrInst>(&I)) {
                if (isSecretValue(IBI->getAddress()))
                    reportIndirectControlFlowError(IBI, F);
            } else if (auto *CB = dyn_cast<CallBase>(&I)) {
                // Direct calls have a non-null getCalledFunction(); skip them.
                // Indirect calls (function pointers) have a null calledFunction
                // and a potentially secret callee operand.
                if (CB->getCalledFunction()) continue;
                if (isSecretValue(CB->getCalledOperand()))
                    reportIndirectControlFlowError(CB, F);
            }
        }
    }
}

PreservedAnalyses SecretBranchElimPass::run(Module &M, ModuleAnalysisManager &AM) {
    bool Changed = false;

    for (Function &F : M) {
        if (F.isDeclaration()) continue;

        checkSecretMemoryAccesses(F);
        checkSecretIndirectControlFlow(F);

        // Collect first to avoid iterator invalidation during transformation.
        SmallVector<CondBrInst *, 8> SecretBranches;
        for (BasicBlock &BB : F)
            for (Instruction &I : BB)
                if (auto *BI = dyn_cast<CondBrInst>(&I))
                    if (isSecretBranch(BI))
                        SecretBranches.push_back(BI);

        for (CondBrInst *BI : SecretBranches) {
            BasicBlock *TrueBB, *FalseBB, *MergeBB;
            if (!checkDiamond(BI, TrueBB, FalseBB, MergeBB) ||
                !checkSpeculatable(TrueBB) ||
                !checkSpeculatable(FalseBB)) {
                reportError(BI, F);
                continue;
            }
            convertToSelect(BI, TrueBB, FalseBB, MergeBB);
            Changed = true;
        }
    }

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
