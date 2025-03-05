add_executable(tests tests.cpp)
target_link_libraries(tests PRIVATE zdb::libzdb Catch2::Catch2WithMain)