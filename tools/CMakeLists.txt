add_executable(zdb zdb.cpp)
target_link_libraries(zdb PRIVATE zdb::libzdb PkgConfig::libedit fmt::fmt)

include(GNUInstallDirs)
install(
    TARGETS zdb
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
