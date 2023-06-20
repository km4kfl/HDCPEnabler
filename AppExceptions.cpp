#include "AppExceptions.h"

ProcessFailure::ProcessFailure(std::string msg) : msg(msg) {
}

std::string ProcessFailure::Message() {
    return msg;
}

ObjectNotInitialized::ObjectNotInitialized() {
}

ObjectNotInitialized::~ObjectNotInitialized() {
}

SuspectBuggyUsage::SuspectBuggyUsage() {

}

SuspectBuggyUsage::~SuspectBuggyUsage() {

}