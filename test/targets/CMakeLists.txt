function(add_test_cpp_executable name)
    add_executable(${name} ${name}.cpp)
    target_compile_options(${name} PRIVATE -g -gdwarf-4 -O0 -pie)
    add_dependencies(tests ${name})
endfunction()

function(add_test_asm_executable name)
    add_executable(${name} ${name}.s)
    target_compile_options(${name} PRIVATE -pie)
    add_dependencies(tests ${name})
endfunction()

add_test_cpp_executable(run_endlessly)
add_test_cpp_executable(end_immediately)
add_test_cpp_executable(hello_zdb)
add_test_cpp_executable(memory)
add_test_cpp_executable(anti_debugger)
add_test_cpp_executable(overloaded)
add_test_cpp_executable(step)

add_test_asm_executable(reg_write)
add_test_asm_executable(reg_read)

add_executable(multi_cu multi_cu_main.cpp multi_cu_other.cpp)
target_compile_options(multi_cu PRIVATE -g -gdwarf-4 -O0 -pie)
add_dependencies(tests multi_cu)



add_test_cpp_executable(marshmallow)
add_library(meow SHARED "libmeow.cpp")
target_compile_options(meow PRIVATE -g -O0 -fPIC -gdwarf-4)
target_link_libraries(marshmallow PRIVATE meow)

