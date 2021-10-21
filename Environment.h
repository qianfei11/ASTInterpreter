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

void get_sys_time() {
    struct timeval tv{};
    struct tm *tm_ptr;
    gettimeofday(&tv, nullptr);
    tm_ptr = localtime(&tv.tv_sec);
    printf("[%d-%02d-%02d %02d:%02d:%02d.%d] ", 1900+tm_ptr->tm_year, 1+tm_ptr->tm_mon,
           tm_ptr->tm_mday, tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec, tv.tv_usec/1000);
}

#define UNKNOWN_RET 0xDEAD0001

#define RED(s) "\033[31;4m"#s"\033[0m"

enum RET_TYPES {
    VOID_RETURN,
    INT_RETURN,
};

/// Heap maps address to a value
class Heap {
    void * ptr;
    int size;

public:
    void setChunk(void * p, int sz) {
        ptr = p;
        size = sz;
    }

    long getChunkPtr() {
        return (long) ptr;
    }

    int getChunkSize() {
        return size;
    }
};

class StackFrame {
    /// StackFrame maps Variable Declaration to Value
    /// Which are either integer or addresses (also represented using an Integer value)
    std::map<Decl *, long> mVars; /* Declaration */
    std::map<Stmt *, long> mExprs; /* Expressions */
    /// The current stmt
    Stmt * mPC; /* Program Counter */

    bool retType = VOID_RETURN; /* enum RET_TYPES */
    int retValue = 0;

    std::map<Heap *, long> mChunks; /* heap info */

public:
    StackFrame() : mVars(), mExprs(), mPC() {
    }

    void bindDecl(Decl* decl, long val) {
        mVars[decl] = val;
    }

    long getDeclVal(Decl * decl) {
        assert (mVars.find(decl) != mVars.end());
        return mVars.find(decl)->second; /* get declaration value */
    }

    void bindStmt(Stmt * stmt, long val) {
        mExprs[stmt] = val;
    }

    long getStmtVal(Stmt * stmt) {
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
        if (retType == VOID_RETURN && retValue == 0) {
            return false;
        } else {
            return true;
        }
    }

    int getRV() {
        if (retType == VOID_RETURN) {
            return 0;
        } else if (retType == INT_RETURN) {
            return retValue;
        } else {
            return UNKNOWN_RET;
        }
    }

    void pushStmtVal(Stmt * stmt, int value) { /* save function's return value */
        mExprs.insert(std::pair<Stmt *, int>(stmt, value));
    }

    bool isExprExist(Stmt * stmt) {
        return mExprs.find(stmt) != mExprs.end();
    }

    void setHeapVal(Heap * heap, long value) {
        mChunks.insert(std::pair<Heap *, long>(heap, value));
    }

    long getHeapVal(Heap * heap) {
        return mChunks[heap];
    }
};

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
        mStack.push_back(StackFrame()); /* save the stack (prevent from segmentation fault) */
        for (TranslationUnitDecl::decl_iterator i = unit->decls_begin(), e = unit->decls_end(); i != e; ++i) { /* traverse the full AST */
            if (auto fDecl = dyn_cast<FunctionDecl>(*i) ) { /* global function */
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
            } else if (auto vDecl = dyn_cast<VarDecl>(*i)) { /* global variable */
                LOG_DEBUG("VarDecl->Name = %s\n", vDecl->getName().data());
                if (vDecl->getType().getTypePtr()->isIntegerType()) {
                    if (vDecl->hasInit()) {
                        mStack.back().bindDecl(vDecl, eval(vDecl->getInit()));
                    } else {
                        mStack.back().bindDecl(vDecl, 0);
                    }
                } else {
                    LOG_DEBUG(RED(TODO) "\n");
                }
            } else {
                LOG_DEBUG(RED(TODO) "\n");
            }
        }
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
        bOp->dumpColor();
//        traverseStack();

        if (bOp->isAssignmentOp()) { /* assignment operation */
            LOG_DEBUG("BinaryOperator is assignment operator\n");
            if (auto declExpr = dyn_cast<DeclRefExpr>(left)) { /* Expr */
                int val = eval(right);
                mStack.back().bindStmt(left, val); /* set statement value */
                Decl * decl = declExpr->getFoundDecl();
                mStack.back().bindDecl(decl, val); /* set declaration value */
            } else if (auto arrExpr = dyn_cast<ArraySubscriptExpr>(left)) {
                if (auto declExpr = dyn_cast<DeclRefExpr>(arrExpr->getLHS()->IgnoreImpCasts())) {
                    Decl * decl = declExpr->getFoundDecl();
                    int val = eval(right);
                    int idx = eval(arrExpr->getRHS());
                    if (auto varDecl = dyn_cast<VarDecl>(decl)) {
                        if (auto arrType = dyn_cast<ConstantArrayType>(varDecl->getType().getTypePtr())) {
                            if (arrType->getElementType().getTypePtr()->isIntegerType()) {
                                int * p = (int *) mStack.back().getDeclVal(varDecl);
                                varDecl->dumpColor();
                                printf(RED(%p) "\n", p);
                                *(p + idx) = val;
                            } else if (arrType->getElementType().getTypePtr()->isCharType()) {
                                char * p = (char *) mStack.back().getDeclVal(varDecl);
                                *(p + idx) = val;
                            } else {
                                LOG_DEBUG(RED(TODO) "\n");
                            }
                        } else {
                            LOG_DEBUG(RED(TODO) "\n");
                        }
                    } else {
                        LOG_DEBUG(RED(TODO) "\n");
                    }
                } else {
                    LOG_DEBUG(RED(TODO) "\n");
                }
            } else {
                LOG_DEBUG(RED(TODO) "\n");
            }
        } else { /* arithmetic operation */
            LOG_DEBUG("BinaryOperator is arithmetic operator\n");
            auto op = bOp->getOpcode();
            int res;
            switch (op) {
                case BO_Add: /* + */
                    res = eval(left) + eval(right);
                    break;
                case BO_Sub: /* - */
                    res = eval(left) - eval(right);
                    break;
                case BO_Mul: /* * */
                    res = eval(left) * eval(right);
                    break;
                case BO_GT: /* > */
                    res = eval(left) > eval(right);
                    break;
                case BO_LT: /* < */
                    res = eval(left) < eval(right);
                    break;
                case BO_EQ: /* == */
                    res = eval(left) == eval(right);
                    break;
                case BO_NE: /* != */
                    res = eval(left) != eval(right);
                    break;
                case BO_GE: /* >= */
                    res = (eval(left) == eval(right)) || (eval(left) > eval(right));
                    break;
                case BO_LE: /* <= */
                    res = (eval(left) == eval(right)) || (eval(left) < eval(right));
                    break;
                default:
                    LOG_DEBUG(RED(TODO) "\n");
                    break;
            }
            /* save statement value */
            if (mStack.back().isExprExist(bOp)) {
                mStack.back().bindStmt(bOp, res);
            } else {
                mStack.back().pushStmtVal(bOp, res);
            }
        }
    }

    void unaryOp(UnaryOperator * uOp) {
        LOG_DEBUG("call unaryOp(UnaryOperator *);\n");
        auto op = uOp->getOpcode();
        auto expr = uOp->getSubExpr();
        int res;
        switch (op) {
            case UO_Minus:
                res = -1 * eval(expr);
                break;
            default:
                LOG_DEBUG(RED(TODO) "\n");
                break;
        }
        mStack.back().pushStmtVal(uOp, res);
    }

    /* Declaration */
    void decl(DeclStmt * declStmt) {
        declStmt->dumpColor();
        for (DeclStmt::decl_iterator it = declStmt->decl_begin(), ie = declStmt->decl_end();
             it != ie; ++ it) {
            Decl * decl = *it;
            if (auto varDecl = dyn_cast<VarDecl>(decl)) {
                LOG_DEBUG("varDecl: %s\n", varDecl->getName().data());
                if (varDecl->getType().getTypePtr()->isIntegerType()) {
                    if (varDecl->hasInit()) {
                        mStack.back().bindDecl(varDecl, eval(varDecl->getInit()));
                    } else {
                        mStack.back().bindDecl(varDecl, 0);
                    }
                } else if (varDecl->getType().getTypePtr()->isArrayType()) {
                    if (auto arrType = dyn_cast<ConstantArrayType>(varDecl->getType().getTypePtr())) {
                        int length = arrType->getSize().getSExtValue();
                        if (arrType->getElementType().getTypePtr()->isIntegerType()) {
                            int * arr = new int[length];
                            for (int i = 0; i < length; i++) {
                                arr[i] = 0;
                            }
                            printf(RED(%p) "\n", arr);
                            mStack.back().bindDecl(varDecl, (long) arr); /* bind array's virtual address */
                        } else if (arrType->getElementType().getTypePtr()->isCharType()) {
                            char * arr = new char[length];
                            for (int i = 0; i < length; i++) {
                                arr[i] = 0;
                            }
                            mStack.back().bindDecl(varDecl, (long) arr); /* bind array's virtual address */
                        } else {
                            LOG_DEBUG(RED(TODO) "\n");
                        }
                    } else {
                        LOG_DEBUG(RED(TODO) "\n");
                    }
                } else {
                    LOG_DEBUG(RED(TODO) "\n");
                }
            }
        }
    }

    /* Declaration References */
    void declRef(DeclRefExpr * declRef) {
        declRef->dumpColor();
        mStack.back().setPC(declRef); /* set PC to current */
        if (declRef->getType()->isIntegerType()) {
            Decl * decl = declRef->getFoundDecl();
            int val = mStack.back().getDeclVal(decl);
            LOG_DEBUG("val = %d\n", val);
            mStack.back().bindStmt(declRef, val);
        } else if (declRef->getType()->isArrayType()) {
            auto varDecl = dyn_cast<VarDecl>(declRef->getFoundDecl());
            if (auto arrType = dyn_cast<ConstantArrayType>(varDecl->getType().getTypePtr())) {
                int * arr = (int *) mStack.back().getDeclVal(varDecl);
                LOG_DEBUG("val = %p\n", arr);
                mStack.back().bindStmt(declRef, (long) arr);
            } else {
                LOG_DEBUG(RED(TODO) "\n");
            }
        } else {
            LOG_DEBUG(RED(TODO) "\n");
        }
    }

    /* Cast */
    void cast(CastExpr * castExpr) {
        castExpr->dumpColor();
        mStack.back().setPC(castExpr);
        if (castExpr->getType()->isIntegerType()) {
            Expr * expr = castExpr->getSubExpr();
            int val = mStack.back().getStmtVal(expr);
            mStack.back().bindStmt(castExpr, val);
        } else {
            LOG_DEBUG(RED(TODO) "\n");
        }
    }

    void arrayExpr(ArraySubscriptExpr *arrExpr) {
        arrExpr->dumpColor();
        mStack.back().setPC(arrExpr);
        if (auto declExpr = dyn_cast<DeclRefExpr>(arrExpr->getLHS()->IgnoreImpCasts())) {
            Decl *decl = declExpr->getFoundDecl();
            int idx = eval(arrExpr->getRHS());
            if (auto varDecl = dyn_cast<VarDecl>(decl)) {
                if (auto arrType = dyn_cast<ConstantArrayType>(varDecl->getType().getTypePtr())) {
                    if (arrType->getElementType().getTypePtr()->isIntegerType()) {
                        int * arr = (int *) mStack.back().getDeclVal(varDecl);
                        mStack.back().bindStmt(arrExpr, *(arr + idx));
                    } else if (arrType->getElementType().getTypePtr()->isCharType()) {
                        char * arr = (char *) mStack.back().getDeclVal(varDecl);
                        mStack.back().bindStmt(arrExpr, *(arr + idx));
                    } else {
                        LOG_DEBUG(RED(TODO) "\n");
                    }
                }
            }
        }
    }

    /// !TODO Support Function Call
    void call(CallExpr * callExpr) { /* function call */
        callExpr->dumpColor();
        mStack.back().setPC(callExpr);
        int val = 0;
        FunctionDecl * callee = callExpr->getDirectCallee();
        if (callee == mInput) {
            printf("Please Input an Integer Value : ");
            scanf("%d", &val);
            mStack.back().bindStmt(callExpr, val);
        } else if (callee == mOutput) {
            Expr * decl = callExpr->getArg(0);
            val = mStack.back().getStmtVal(decl);
            printf(RED(Result Value : %d) "\n", val);
        } else if (callee == mMalloc) {
            Expr * decl = callExpr->getArg(0);
            val = mStack.back().getStmtVal(decl);
        } else if (callee == mFree) {
            Expr * decl = callExpr->getArg(0);
            val = mStack.back().getStmtVal(decl);
        } else { /* other functions */
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
        expr = expr->IgnoreImpCasts(); /* ignore cast */
        if (auto decl = dyn_cast<DeclRefExpr>(expr)) {
            declRef(decl);
            return mStack.back().getStmtVal(decl);
        } else if (auto intLiteral = dyn_cast<IntegerLiteral>(expr)) { /* int */
            return intLiteral->getValue().getSExtValue();
        } else if (auto bOp = dyn_cast<BinaryOperator>(expr)) { /* binary operator */
            binOp(bOp);
            return mStack.back().getStmtVal(bOp);
        } else if (auto callExpr = dyn_cast<CallExpr>(expr)) { /* call expression */
            return mStack.back().getStmtVal(callExpr);
        } else if (auto uOp = dyn_cast<UnaryOperator>(expr)) {
            unaryOp(uOp);
            return mStack.back().getStmtVal(uOp);
        } else if (auto arrExpr = dyn_cast<ArraySubscriptExpr>(expr)) {
            int val = mStack.back().getStmtVal(arrExpr);
            LOG_DEBUG("val = %d\n", val);
            return val;
//            return mStack.back().getStmtVal(arrExpr);
        } else { /* TODO */
            LOG_DEBUG(RED(TODO) "\n");
            return 0;
        }
    }

    void traverseStack() { /* for debugging */
        LOG_DEBUG("traverse mStack (%lu)\n", mStack.size());
        for (auto & it : mStack) {
            it.getPC()->dumpColor();
        }
    }

    void setReturnStmt(ReturnStmt * returnStmt) {
        returnStmt->dumpColor();
        int val = eval(returnStmt->getRetValue());
        mStack.back().setRV(INT_RETURN, val);
    }
};
