#include <lib7etsuo/core/log/L7_Logger.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  L7_LOG_MSG_TRUSTED(L7_LOG_INFO, "My Module", "%s%i","The answer to the universe is ", 42);
  L7_LOG_MSG(L7_LOG_ERROR, "My Module", "This input isn't trusted %s%i string format will not work.");
}
