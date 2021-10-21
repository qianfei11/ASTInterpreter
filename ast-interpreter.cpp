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
    virtual ~InterpreterVisitor() = default;

    /* visit binary operator */
    virtual void VisitBinaryOperator(BinaryOperator * bOp) {
        LOG_DEBUG("call VisitBinaryOperator(BinaryOperator *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitBinaryOperator(BinaryOperator *)\n");
            VisitStmt(bOp);
            mEnv->binOp(bOp);
        }
        LOG_DEBUG("finish VisitBinaryOperator(BinaryOperator *)\n");
    }

    virtual void VisitUnaryOperator(UnaryOperator * uOp) {
        LOG_DEBUG("call VisitUnaryOperator(UnaryOperator *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitUnaryOperator(UnaryOperator *)\n");
            VisitStmt(uOp);
            mEnv->unaryOp(uOp);
        }
        LOG_DEBUG("finish VisitUnaryOperator(UnaryOperator *)\n");
    }

    /* visit declaration reference expression */
    virtual void VisitDeclRefExpr(DeclRefExpr * declRefExpr) {
        LOG_DEBUG("call VisitDeclRefExpr(DeclRefExpr *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitDeclRefExpr(DeclRefExpr *)\n");
            VisitStmt(declRefExpr);
            mEnv->declRef(declRefExpr);
        }
        LOG_DEBUG("finish VisitDeclRefExpr(DeclRefExpr *)\n");
    }

    virtual void VisitArraySubscriptExpr(ArraySubscriptExpr * arrExpr) {
        LOG_DEBUG("call ArraySubscriptExpr(ArraySubscriptExpr *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in ArraySubscriptExpr(ArraySubscriptExpr *)\n");
            VisitStmt(arrExpr);
            mEnv->arrayExpr(arrExpr);
        }
        LOG_DEBUG("finish ArraySubscriptExpr(ArraySubscriptExpr *)\n");
    }

    /* visit cast expression */
    virtual void VisitCastExpr(CastExpr * castExpr) {
        LOG_DEBUG("call VisitCastExpr(CastExpr *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitCastExpr(CastExpr *)\n");
            VisitStmt(castExpr);
            mEnv->cast(castExpr);
        }
        LOG_DEBUG("finish VisitCastExpr(CastExpr *)\n");
    }

    /* visit call expression */
    virtual void VisitCallExpr(CallExpr * callExpr) {
        LOG_DEBUG("call VisitCallExpr(CallExpr *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitCallExpr(CallExpr *)\n");
            VisitStmt(callExpr);
            mEnv->call(callExpr);
            /* recursion */
            LOG_DEBUG("start recursion\n");
            if (FunctionDecl *funcDecl = callExpr->getDirectCallee()) {
                if (!(funcDecl->getName().equals("GET") || funcDecl->getName().equals("PRINT") ||
                      funcDecl->getName().equals("MALLOC") || funcDecl->getName().equals("FREE"))) {
//                    mEnv->traverseStack();
                    Visit(funcDecl->getBody());
                    int rv = mEnv->mStack.back().getRV();
                    mEnv->mStack.pop_back();
                    mEnv->mStack.back().pushStmtVal(callExpr, rv); /* save function's return value */
                }
            }
        }
        LOG_DEBUG("finish VisitCallExpr(CallExpr *)\n");
    }

    /* visit declaration statement */
    virtual void VisitDeclStmt(DeclStmt * declStmt) {
        LOG_DEBUG("call VisitDeclStmt(DeclStmt *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitDeclStmt(DeclStmt *)\n");
            mEnv->decl(declStmt);
        }
        LOG_DEBUG("finish VisitDeclStmt(DeclStmt *)\n");
    }

    /* visit if statement */
    virtual void VisitIfStmt(IfStmt * ifStmt) {
        LOG_DEBUG("call VisitIfStmt(IfStmt *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitIfStmt(IfStmt *)\n");
            if (mEnv->eval(ifStmt->getCond())) { /* judge condition */
                Visit(ifStmt->getThen());
            } else {
                if (ifStmt->getElse()) {
                    Visit(ifStmt->getElse());
                }
            }
        }
        LOG_DEBUG("finish VisitIfStmt(IfStmt *)\n");
    }

    /* visit return statement */
    virtual void VisitReturnStmt(ReturnStmt * returnStmt) {
        LOG_DEBUG("call VisitReturnStmt(ReturnStmt *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitReturnStmt(ReturnStmt *)\n");
            Visit(returnStmt->getRetValue());
            mEnv->setReturnStmt(returnStmt);
        }
        LOG_DEBUG("finish VisitReturnStmt(ReturnStmt *)\n");
    }

    /* visit while statement */
    virtual void VisitWhileStmt(WhileStmt * whileStmt) {
        LOG_DEBUG("call VisitWhileStmt(WhileStmt *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitWhileStmt(WhileStmt *)\n");
            while (mEnv->eval(whileStmt->getCond())) {
                Visit(whileStmt->getBody());
            }
        }
        LOG_DEBUG("finish VisitWhileStmt(WhileStmt *)\n");
    }

    /* visit for statement */
    virtual void VisitForStmt(ForStmt * forStmt) {
        LOG_DEBUG("call VisitForStmt(ForStmt *)\n");
        if (!mEnv->mStack.back().haveRV()) {
            LOG_DEBUG("in VisitForStmt(ForStmt *)\n");
            if (forStmt->getInit()) {
                Visit(forStmt->getInit());
            }
            for (; mEnv->eval(forStmt->getCond()); Visit(forStmt->getInc())) {
                Visit(forStmt->getBody());
            }
        }
        LOG_DEBUG("finish VisitForStmt(ForStmt *)\n");
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
    ~InterpreterConsumer() override {}

    void HandleTranslationUnit(clang::ASTContext &Context) override { /* traverse AST */
        TranslationUnitDecl * decl = Context.getTranslationUnitDecl(); /* get declarations */
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
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
            clang::CompilerInstance &Compiler, llvm::StringRef InFile) override {
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
