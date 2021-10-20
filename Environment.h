//==--- tools/clang-check/ClangInterpreter.cpp - Clang Interpreter tool --------------===//
//===----------------------------------------------------------------------===//
#include <cstdio>
#include <sys/time.h>

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"

using namespace clang;

enum LOG_LEVEL {
    LOG_LEVEL_OFF = -3,
    LOG_LEVEL_ERROR = -2,
    LOG_LEVEL_WARN = -1,
    LOG_LEVEL_INFO = 0,
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_ALL = 2,
};

#define LOG_DEBUG(format,...) \
do { \
     	if (log_level >= LOG_LEVEL_DEBUG) {	\
		    get_sys_time();	\
     		printf("[%20s] [%6d] [DEBUG] " format "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
	    }	\
} while(0)
#define LOG_INFO(format,...) \
do { \
     	if (log_level >= LOG_LEVEL_INFO) {	\
		    get_sys_time();	\
     		printf("[%20s] [%6d] [INFO ] " format "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
	    }	\
} while(0)
#define LOG_WARN(format,...) \
do { \
     	if (log_level >= LOG_LEVEL_WARN) {	\
		    get_sys_time();	\
     		printf("[%20s] [%6d] [WARN ] " format "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
	    }	\
} while(0)
#define LOG_ERROR(format,...) \
do { \
     	if (log_level >= LOG_LEVEL_ERROR) {	\
		    get_sys_time();	\
     		printf("[%20s] [%6d] [ERROR] " format "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
	    }	\
} while(0)

int log_level = LOG_LEVEL_ALL;

void get_sys_time(void) {
    struct timeval tv;
    struct tm *tm_ptr;
    gettimeofday(&tv, NULL);
    tm_ptr = localtime(&tv.tv_sec);
    printf("[%d-%02d-%02d %02d:%02d:%02d.%d] ", 1900+tm_ptr->tm_year, 1+tm_ptr->tm_mon,
           tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec, tv.tv_usec/1000);
}

#define UNKOWN_RET 0xDEAD0001

enum RET_TYPES {
    VOID_RETURN,
    INT_RETURN,
};

class StackFrame {
    /// StackFrame maps Variable Declaration to Value
    /// Which are either integer or addresses (also represented using an Integer value)
    std::map<Decl*, int> mVars; /* Declaration */
    std::map<Stmt*, int> mExprs; /* Expressions */
    /// The current stmt
    Stmt * mPC; /* Program Counter */

    bool retType; /* enum RET_TYPES */
    int retValue;
public:
    StackFrame() : mVars(), mExprs(), mPC() {
    }

    void bindDecl(Decl* decl, int val) {
        mVars[decl] = val;
    }

    int getDeclVal(Decl * decl) {
        assert (mVars.find(decl) != mVars.end());
        return mVars.find(decl)->second; /* get declaration value */
    }

    void bindStmt(Stmt * stmt, int val) {
        mExprs[stmt] = val;
    }

    int getStmtVal(Stmt * stmt) {
        assert (mExprs.find(stmt) != mExprs.end());
        return mExprs[stmt]; /* get statement */
    }

    void setPC(Stmt * stmt) {
        mPC = stmt;
    }

    Stmt * getPC() {
        return mPC; /* get program counter */
    }

    void setRV(bool rt, int rv) {
        retType = rt;
        retValue = rv;
    }

    bool haveRV() {
        if (retType && retValue) {
            return true;
        } else {
            return false;
        }
    }

    int getRV() {
        if (retType == VOID_RETURN) {
            return 0;
        } else if (retType == INT_RETURN) {
            return retValue;
        } else {
            return UNKOWN_RET;
        }
    }

    void pushStmtVal(Stmt * stmt, int value) { /* save function's return value */
        mExprs.insert(std::pair<Stmt *, int>(stmt, value));
    }

    bool isExprExist(Stmt * stmt) {
        return mExprs.find(stmt) != mExprs.end();
    }
};

/// Heap maps address to a value
/*
class Heap {
public:
   int Malloc(int size) ;
   void Free (int addr) ;
   void Update(int addr, int val) ;
   int get(int addr);
};
*/

class Environment {
    FunctionDecl * mFree;				/// Declartions to the built-in functions
    FunctionDecl * mMalloc;
    FunctionDecl * mInput;
    FunctionDecl * mOutput;

    FunctionDecl * mEntry;
public:
    std::vector<StackFrame> mStack; /* Stack */

    /// Get the declartions to the built-in functions
    Environment() : mStack(), mFree(), mMalloc(), mInput(), mOutput(), mEntry() {
    }

    /// Initialize the Environment
    void init(TranslationUnitDecl * unit) { /* traverse functions & global variables */
        LOG_DEBUG("call init(TranslationUnitDecl *);\n");
        unit->dumpColor();
        for (TranslationUnitDecl::decl_iterator i = unit->decls_begin(), e = unit->decls_end(); i != e; ++i) { /* traverse the full AST */
            if (FunctionDecl * fDecl = dyn_cast<FunctionDecl>(*i) ) { /* global function */
                LOG_DEBUG("FunctionDecl->Name = %s\n", fDecl->getName().data());
                if (fDecl->getName().equals("FREE")) {
                    mFree = fDecl;
                } else if (fDecl->getName().equals("MALLOC")) {
                    mMalloc = fDecl;
                } else if (fDecl->getName().equals("GET")) {
                    mInput = fDecl;
                } else if (fDecl->getName().equals("PRINT")) {
                    mOutput = fDecl;
                } else if (fDecl->getName().equals("main")) {
                    mEntry = fDecl;
                }
            } else if (VarDecl * vDecl = dyn_cast<VarDecl>(*i)) { /* global variable */
                LOG_DEBUG("VarDecl->Name = %s\n", vDecl->getName().data());
                if (vDecl->getType().getTypePtr()->isIntegerType()) {
                    if (vDecl->hasInit()) {
                        mStack.back().bindDecl(vDecl, eval(vDecl->getInit()));
                    } else {
                        mStack.back().bindDecl(vDecl, 0);
                    }
                } else {
                    LOG_DEBUG("TODO");
                }
            }
        }
//        mStack.push_back(StackFrame()); /* save the stack */
    }

    FunctionDecl * getEntry() {
        LOG_DEBUG("call getEntry();\n");
        LOG_DEBUG("FunctionDecl->Name = %s\n", mEntry->getName().data());
        return mEntry; /* get main entry */
    }

    /// !TODO Support comparison operation
    /* Binary Operation */
    void binOp(BinaryOperator *bOp) {
        LOG_DEBUG("call binOp(BinaryOperator *);\n");
        Expr * left = bOp->getLHS(); /* get left-hand side */
        Expr * right = bOp->getRHS(); /* get right-hand side */
        left->dumpColor();
        right->dumpColor();

        if (bOp->isAssignmentOp()) { /* assignment operation */
            LOG_DEBUG("BinaryOperator is assignment operator\n");
            LOG_DEBUG("traverse mStack (%lu)\n", mStack.size());
            for (auto it = mStack.begin(); it != mStack.end(); ++it) {
                it->getPC()->dumpColor();
            }
            if (DeclRefExpr * declExpr = dyn_cast<DeclRefExpr>(left)) { /* Expr */
                int val = eval(right);
                mStack.back().bindStmt(left, val); /* set statement value */
                Decl * decl = declExpr->getFoundDecl();
                mStack.back().bindDecl(decl, val); /* set declaration value */
            } else {
                ;
            }
        } else { /* arithmetic operation */
            LOG_DEBUG("BinaryOperator is arithmetic operator\n");
            auto op = bOp->getOpcode();
            switch (op) {
                default:
                    break;
            }
        }
    }

    /* Declaration */
    void decl(DeclStmt * declStmt) {
        for (DeclStmt::decl_iterator it = declStmt->decl_begin(), ie = declStmt->decl_end();
             it != ie; ++ it) {
            Decl * decl = *it;
            if (VarDecl * varDecl = dyn_cast<VarDecl>(decl)) {
                LOG_DEBUG("varDecl: %s\n", varDecl->getName().data());
                mStack.back().bindDecl(varDecl, 0);
            }
        }
    }

    /* Declaration References */
    void declRef(DeclRefExpr * declRef) {
        mStack.back().setPC(declRef);
        if (declRef->getType()->isIntegerType()) {
            Decl* decl = declRef->getFoundDecl();

            int val = mStack.back().getDeclVal(decl);
            mStack.back().bindStmt(declRef, val);
        }
    }

    /* Cast */
    void cast(CastExpr * castExpr) {
        mStack.back().setPC(castExpr);
        if (castExpr->getType()->isIntegerType()) {
            Expr * expr = castExpr->getSubExpr();
            int val = mStack.back().getStmtVal(expr);
            mStack.back().bindStmt(castExpr, val);
        }
    }

    /// !TODO Support Function Call
    void call(CallExpr * callExpr) { /* function call */
        mStack.back().setPC(callExpr);
        int val = 0;
        FunctionDecl * callee = callExpr->getDirectCallee();
        if (callee == mInput) {
            llvm::errs() << "Please Input an Integer Value : ";
            scanf("%d", &val);

            mStack.back().bindStmt(callExpr, val);
        } else if (callee == mOutput) {
            Expr * decl = callExpr->getArg(0);
            val = mStack.back().getStmtVal(decl);
            llvm::errs() << val;
        } else if (callee == mMalloc) {
            ;
        } else if (callee == mFree) {
            ;
        } else {
            std::vector<int> args;
            for (auto arg = callExpr->arg_begin(), e = callExpr->arg_end(); arg != e; arg++) {
                args.push_back(eval(*arg));
            }
            mStack.push_back(StackFrame());
            int idx = 0;
            for (auto param = callee->param_begin(), e = callee->param_end(); param != e; param++, idx++) {
                mStack.back().bindDecl(*param, args[idx]);
            }
        }
    }

    int eval(Expr * expr) {
        expr = expr->IgnoreImpCasts();
        if (auto decl = dyn_cast<DeclRefExpr>(expr)) {
            declRef(decl);
            return mStack.back().getStmtVal(decl); /* ??? */
        } else if (auto intLiteral = dyn_cast<IntegerLiteral>(expr)) {
            return intLiteral->getValue().getSExtValue();
        } else {
            LOG_DEBUG("TODO");
        }
    }
};
