#include "llvm/Transforms/Utils/SecretTaint.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// Renamed to avoid collision with llvm::FunctionSummary in ModuleSummaryIndex.h
struct SecretFuncSummary {
    bool returnsSecret = false;
    SmallVector<bool, 8> secretParams;
};

// ---- Helpers ----

static StringRef getAnnotationString(Value *V) {
    if (auto *BC = dyn_cast<BitCastOperator>(V))
        V = BC->getOperand(0);
    if (auto *GV = dyn_cast<GlobalVariable>(V))
        if (GV->hasInitializer())
            if (auto *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer()))
                if (CDA->isCString())
                    return CDA->getAsCString();
    return "";
}

static bool isSecretAnnotation(CallInst *CI) {
    Function *Callee = CI->getCalledFunction();
    if (!Callee || !Callee->getName().starts_with("llvm.var.annotation"))
        return false;
    return getAnnotationString(CI->getArgOperand(1)) == "secret";
}

// getMetadata is protected on Value — must cast to Instruction first.
static bool isSecretInst(Value *V) {
    if (auto *I = dyn_cast<Instruction>(V))
        return I->getMetadata("secret") != nullptr;
    return false;
}

// ---- Intraprocedural taint for one function ----

static SecretFuncSummary analyzeFunction(
        Function &F,
        const SmallPtrSetImpl<Value *> &ExtraSecretArgs,
        MDNode *SecretMD) {

    SecretFuncSummary Summary;
    Summary.secretParams.resize(F.arg_size(), false);

    SmallPtrSet<Value *, 32> TaintedPtrs;
    SmallPtrSet<Value *, 32> TaintedVals;

    // Seed 1: llvm.var.annotation intrinsics.
    // Collect then erase: the annotation call takes the alloca's address,
    // which makes the alloca look "escaped" and blocks mem2reg from promoting
    // it to SSA.  Once we've seeded from it, the call is no longer needed.
    SmallVector<CallInst *, 8> AnnotationCalls;
    for (auto &BB : F)
        for (auto &I : BB)
            if (auto *CI = dyn_cast<CallInst>(&I))
                if (isSecretAnnotation(CI)) {
                    Value *Ptr = CI->getArgOperand(0);
                    TaintedPtrs.insert(Ptr);
                    errs() << "[SecretTaint] Annotation seed: "
                           << Ptr->getName() << " in " << F.getName() << "\n";
                    AnnotationCalls.push_back(CI);
                }
    for (CallInst *CI : AnnotationCalls)
        CI->eraseFromParent();

    // Seed 2: parameters marked secret by caller
    for (auto &Arg : F.args()) {
        if (ExtraSecretArgs.count(&Arg)) {
            TaintedVals.insert(&Arg);
            Summary.secretParams[Arg.getArgNo()] = true;
            errs() << "[SecretTaint] Param seed: arg " << Arg.getArgNo()
                   << " in " << F.getName() << "\n";
        }
    }

    // Fixed-point intraprocedural propagation
    bool Changed = true;
    while (Changed) {
        Changed = false;
        for (auto &BB : F) {
            for (auto &I : BB) {

                // Store: if value being stored is secret, mark ptr and store.
                if (auto *SI = dyn_cast<StoreInst>(&I)) {
                    bool ValSecret = TaintedVals.count(SI->getValueOperand());
                    bool PtrSecret = TaintedPtrs.count(SI->getPointerOperand());
                    if (ValSecret || PtrSecret) {
                        if (TaintedPtrs.insert(SI->getPointerOperand()).second)
                            Changed = true;
                        if (!SI->getMetadata("secret")) {
                            SI->setMetadata("secret", SecretMD);
                            errs() << "[SecretTaint] Tainted store: " << I << "\n";
                            Changed = true;
                        }
                    }
                    continue;
                }

                // Skip already-tainted values
                if (TaintedVals.count(&I))
                    continue;

                bool Taint = false;

                if (auto *LI = dyn_cast<LoadInst>(&I)) {
                    // Load from secret ptr produces secret value
                    Taint = TaintedPtrs.count(LI->getPointerOperand()) > 0;
                } else if (auto *CI = dyn_cast<CallInst>(&I)) {
                    // Skip annotation intrinsics
                    Function *Callee = CI->getCalledFunction();
                    if (Callee && Callee->getName().starts_with("llvm.var.annotation"))
                        continue;
                    // Taint call result if any argument is secret
                    for (auto &Op : CI->args())
                        if (TaintedVals.count(Op.get())) { Taint = true; break; }
                } else {
                    // Any other instruction: tainted if any operand is
                    for (auto &Op : I.operands())
                        if (TaintedVals.count(Op.get())) { Taint = true; break; }
                }

                if (Taint) {
                    TaintedVals.insert(&I);
                    I.setMetadata("secret", SecretMD);
                    Changed = true;
                    errs() << "[SecretTaint] Tainted: " << I << "\n";
                }
            }
        }
    }

    // Record whether any return is secret
    for (auto &BB : F)
        if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator()))
            if (RI->getReturnValue() && TaintedVals.count(RI->getReturnValue())) {
                Summary.returnsSecret = true;
                RI->setMetadata("secret", SecretMD);
            }

    return Summary;
}

// ---- Module pass entry point ----

PreservedAnalyses SecretTaintPass::run(Module &M, ModuleAnalysisManager &AM) {
    LLVMContext &Ctx = M.getContext();
    MDNode *SecretMD = MDNode::get(Ctx, {});

    // Bottom-up order: callees before callers
    SmallVector<Function *, 16> BottomUpOrder;
    SmallPtrSet<Function *, 16> Visited;

    std::function<void(Function *)> DFS = [&](Function *F) {
        if (!F || F->isDeclaration() || !Visited.insert(F).second)
            return;
        for (auto &BB : *F)
            for (auto &I : BB)
                if (auto *CI = dyn_cast<CallInst>(&I))
                    if (Function *Callee = CI->getCalledFunction())
                        DFS(Callee);
        BottomUpOrder.push_back(F);
    };

    for (auto &F : M)
        DFS(&F);

    DenseMap<Function *, SecretFuncSummary> Summaries;

    // Iterate to a module-level fixed point
    bool ModuleChanged = true;
    while (ModuleChanged) {
        ModuleChanged = false;

        for (Function *F : BottomUpOrder) {
            // Find parameters that callers pass secret values into
            SmallPtrSet<Value *, 8> SecretArgs;
            for (auto &OtherF : M) {
                if (&OtherF == F) continue;
                for (auto &BB : OtherF) {
                    for (auto &I : BB) {
                        auto *CI = dyn_cast<CallInst>(&I);
                        if (!CI || CI->getCalledFunction() != F) continue;
                        for (unsigned i = 0; i < CI->arg_size(); ++i) {
                            // Use isSecretInst to safely check metadata
                            if (isSecretInst(CI->getArgOperand(i))) {
                                if (i < F->arg_size()) {
                                    auto ArgIt = F->arg_begin();
                                    std::advance(ArgIt, i);
                                    SecretArgs.insert(&*ArgIt);
                                }
                            }
                        }
                    }
                }
            }

            SmallVector<bool, 8> OldSecretParams = Summaries[F].secretParams;
            bool OldReturnsSecret = Summaries[F].returnsSecret;
            SecretFuncSummary NewSummary = analyzeFunction(*F, SecretArgs, SecretMD);
            Summaries[F] = std::move(NewSummary);

            // If secretParams changed, a callee will need reanalysis next round.
            if (Summaries[F].secretParams != OldSecretParams)
                ModuleChanged = true;

            // If return taint status changed, taint call sites in callers
            if (Summaries[F].returnsSecret && !OldReturnsSecret) {
                ModuleChanged = true;
                for (auto &OtherF : M)
                    for (auto &BB : OtherF)
                        for (auto &I : BB)
                            if (auto *CI = dyn_cast<CallInst>(&I))
                                if (CI->getCalledFunction() == F && !CI->getMetadata("secret")) {
                                    CI->setMetadata("secret", SecretMD);
                                    errs() << "[SecretTaint] Call result tainted: " << *CI << "\n";
                                }
            }

            // If any call in F now passes a secret arg to a callee whose summary
            // doesn't yet reflect that parameter as secret, trigger another round
            // so the callee is reanalyzed with the updated argument information.
            for (auto &BB2 : *F) {
                for (auto &I2 : BB2) {
                    auto *CI2 = dyn_cast<CallInst>(&I2);
                    if (!CI2) continue;
                    Function *Callee2 = CI2->getCalledFunction();
                    if (!Callee2 || Callee2->isDeclaration()) continue;
                    auto &CSum = Summaries[Callee2];
                    for (unsigned i = 0; i < CI2->arg_size() && i < Callee2->arg_size(); ++i) {
                        if (isSecretInst(CI2->getArgOperand(i)) &&
                                (CSum.secretParams.size() <= i || !CSum.secretParams[i])) {
                            ModuleChanged = true;
                        }
                    }
                }
            }
        }
    }

    return PreservedAnalyses::all();
}
