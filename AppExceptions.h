#pragma once
#include <optional>
#include <string>

class ProcessFailure : public std::exception {
private:
    std::string msg;
public:
    ProcessFailure(std::string msg);
    std::string Message();
};

class OverflowFailure : public std::exception {
};

class ObjectNotInitialized : public std::exception {
public:
    ObjectNotInitialized();
    ~ObjectNotInitialized();
};

class SuspectBuggyUsage : public std::exception {
public:
    SuspectBuggyUsage();
    ~SuspectBuggyUsage();
};

#define STR(x) #x
#define STR2(x) STR(x)
// TODO: replace everything with this nice macro to automate building the error message and help with errors across
//       different versions
#define THROW_MSG(exp) __FUNCTION__ ":" __FILE__ ":" STR2(__LINE__) ":" STR(exp)
#define HRESULT_THROW(exp) if (FAILED((exp))) { throw ProcessFailure(THROW_MSG(exp)); }
#define BOOL_THROW(exp) if ((exp) == FALSE) { throw ProcessFailure(THROW_MSG(exp)); }
