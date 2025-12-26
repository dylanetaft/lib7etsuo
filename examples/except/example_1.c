#include <lib7etsuo/core/except/L7_Except.h>
#include <stdio.h>

const L7_Except_T ExampleException_BaseException = { &ExampleException_BaseException,"Base Exception Occurred" };
const L7_Except_T ExampleException_SpecificException = { &ExampleException_SpecificException,"Specific Exception Occurred" };


int main(int argc, char *argv[]) {
    int a = 10;

    L7_TRY {
        if (a != 20) {
            L7_RAISE(ExampleException_SpecificException);
        } 
    }
    L7_EXCEPT (ExampleException_SpecificException) {
        fprintf(stderr, "Whoa, look at that!\n");
        fprintf(stderr, "Error: %s\n", L7_Except_frame.exception->reason);
    }
    L7_FINALLY {}
    L7_END_TRY;

    return 0;
}
