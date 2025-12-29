#include <lib7etsuo/core/log/L7_Logger.h>
#include <lib7etsuo/core/except/L7_Except.h>
#include <stdio.h>

L7_DECLARE_MODULE_EXCEPTION(MyModule)


int main(int argc, char *argv[]) {
  L7_LOG_MSG_TRUSTED(L7_LOG_INFO, "MyModule", "%s%i","The answer to the universe is ", 42);
  L7_LOG_MSG(L7_LOG_ERROR, "MyModule", "This input isn't trusted %s%i string format will not work.");
  L7_Except_T NoSuchValException = {
      &NoSuchValException,
      "No such value exception"
  };
  L7_TRY {
    L7_RAISE_MSG_TRUSTED(MyModule,NoSuchValException, "Log and also raise an exception");
  }
  L7_EXCEPT(NoSuchValException) {
    L7_LOG_MSG(L7_LOG_ERROR, "MyModule", "Caught exception: NoSuchValException");
  } L7_END_TRY;

return 0;
}
