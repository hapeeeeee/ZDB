add_library(libzdb 
    process.cpp 
    pipe.cpp 
    registers.cpp 
    breakpoint_site.cpp 
    disassembler.cpp 
    watchpoint.cpp 
    syscall.cpp
    elf.cpp
    types.cpp
)
target_link_libraries(libzdb PRIVATE Zydis::Zydis)
add_library(zdb::libzdb ALIAS libzdb)

set_target_properties(
    libzdb
    PROPERTIES OUTPUT_NAME zdb
)

target_compile_features(libzdb PUBLIC cxx_std_17)

target_include_directories(
    libzdb
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src/include
)

include(GNUInstallDirs)
install(
    TARGETS libzdb
    EXPORT zdb-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(
    DIRECTORY ${PROJECT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(
    EXPORT zdb-targets
    FILE zdb-config.cmake
    NAMESPACE zdb::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/zdb
)