add_library(libzdb libzdb.cpp)
add_library(zdb::libzdb ALIAS libzdb)
set_target_properties(
    libzdb
    PROPERTIES OUTPUT_NAME zdb
)
target_compile_features(libzdb PUBLIC cxx_std_17)
target_include_directories(
    libzdb
    PRIVATE include
    PUBLIC ${CMAKE_SOURCE_DIR}/include
)