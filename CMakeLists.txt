cmake_minimum_required(VERSION 3.24)
project(chrome_elf_proxy)

# Flags
add_compile_options(/MT /std:c++latest)

# Polyhook2
add_subdirectory(deps/PolyHook_2_0)

# Create the dll
add_library(chrome_elf SHARED main.cc)
target_link_libraries(chrome_elf PolyHook_2)
