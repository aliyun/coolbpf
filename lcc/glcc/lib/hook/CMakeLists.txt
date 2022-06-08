add_library(hook SHARED
            hook.c 
            )

set(CMAKE_C_FLAGS "-ldl")