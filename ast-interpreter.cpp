//==--- tools/clang-check/ClangInterpreter.cpp - Clang Interpreter tool --------------===//
//===----------------------------------------------------------------------===//

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/EvaluatedExprVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"

using namespace clang;

#include "Environment.h"

/* Visitor */
class InterpreterVisitor :
        public EvaluatedExprVisitor<InterpreterVisitor> {
public:
    explicit InterpreterVisitor(const ASTContext &context, Environment * env)
            : EvaluatedExprVisitor(context), mEnv(env) {}
    virtual ~InterpreterVisitor() {}

    /* visit binary operator */
    virtual void VisitBinaryOperator (BinaryOperator * bop) {
        LOG_DEBUG("call VisitBinaryOperator(BinaryOperator *)\n");
        VisitStmt(bop);
        bop->dumpColor();
        mEnv->binOp(bop);
        LOG_DEBUG("finish VisitBinaryOperator(BinaryOperator *)\n");
    }

    /* visit declaration reference expression */
    virtual void VisitDeclRefExpr(DeclRefExpr * expr) {
        LOG_DEBUG("call VisitDeclRefExpr(DeclRefExpr *)\n");
        VisitStmt(expr);
        expr->dumpColor();
        mEnv->declRef(expr);
        LOG_DEBUG("finish VisitDeclRefExpr(DeclRefExpr *)\n");
    }

    /* visit cast expression */
    virtual void VisitCastExpr(CastExpr * expr) {
        LOG_DEBUG("call VisitCastExpr(CastExpr *)\n");
        VisitStmt(expr);
        expr->dumpColor();
        mEnv->cast(expr);
        LOG_DEBUG("finish VisitCastExpr(CastExpr *)\n");
    }

    /* visit call expression */
    virtual void VisitCallExpr(CallExpr * call) {
        LOG_DEBUG("call VisitCallExpr(CallExpr *)\n");
        VisitStmt(call);
        call->dumpColor();
        mEnv->call(call);
        /* recursion */
        LOG_DEBUG("start recursion\n");
        if (FunctionDecl *funcDecl = call->getDirectCallee()) {
            if (!(funcDecl->getName().equals("GET") || funcDecl->getName().equals("PRINT") || funcDecl->getName().equals("MALLOC") || funcDecl->getName().equals("FREE"))) {
                Visit(funcDecl->getBody());
                int rv = mEnv->mStack.back().getRV();
                mEnv->mStack.pop_back();
                mEnv->mStack.back().pushStmtVal(call, rv); /* save function's return value */
            }
        }
        LOG_DEBUG("finish VisitCallExpr(CallExpr *)\n");
    }

    /* visit declaration statement */
    virtual void VisitDeclStmt(DeclStmt * declStmt) {
        LOG_DEBUG("call VisitDeclStmt(DeclStmt *)\n");
        declStmt->dumpColor();
        mEnv->decl(declStmt);
        LOG_DEBUG("finish VisitDeclStmt(DeclStmt *)\n");
    }

private:
    Environment * mEnv;
};

/* AST Consumer */
class InterpreterConsumer : public ASTConsumer {
public:
    explicit InterpreterConsumer(const ASTContext& context) : mEnv(),
                                                              mVisitor(context, &mEnv) {
    }
    virtual ~InterpreterConsumer() {}

    virtual void HandleTranslationUnit(clang::ASTContext &Context) { /* traverse AST */
        TranslationUnitDecl * decl = Context.getTranslationUnitDecl(); /* get delarations */
        LOG_DEBUG("Successfully get declarations\n");
        mEnv.init(decl); /* init environment */
        LOG_DEBUG("Successfully init environment\n");

        FunctionDecl * entry = mEnv.getEntry(); /* get main function */
        LOG_DEBUG("Successfully get entry (%s)\n", entry->getName().data());
        mVisitor.VisitStmt(entry->getBody()); /* traverse statement */
        LOG_DEBUG("Successfully traverse statements\n");
    }

private:
    Environment mEnv; /* Environment */
    InterpreterVisitor mVisitor;
};

/* Interpreter Class */
class InterpreterClassAction : public ASTFrontendAction {
public:
    virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
            clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
        return std::unique_ptr<clang::ASTConsumer>(
                new InterpreterConsumer(Compiler.getASTContext()));
    }
};

int main (int argc, char ** argv) {
    if (argc > 1) {
        clang::tooling::runToolOnCode(
                std::unique_ptr<clang::FrontendAction>(new InterpreterClassAction), /* Action */
                argv[1] /* Code String */
        );
    }
}
