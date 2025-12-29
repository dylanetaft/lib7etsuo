#include <lib7etsuo/core/mem/L7_Arena.h>
#include <stdio.h>



int main(int argc, char *argv[]) {

  L7_Arena_T arena = L7_Arena_new();
  void *some_memory = L7_ARENA_ALLOC(arena, 1024);

return 0;
}
