#include <lib7etsuo/core/log/L7_Logger.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  L7_LOG_MSG(L7_LOG_INFO, "My Module", "%s%i\n","The answer to the universe is ", 42);
}
