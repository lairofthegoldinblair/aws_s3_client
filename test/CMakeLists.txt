add_executable(v4_signing_test v4_signing_test.cc)

target_compile_definitions(v4_signing_test PUBLIC AWS_TEST_SUITE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/aws-sig-v4-test-suite/aws-sig-v4-test-suite/")

target_link_libraries( v4_signing_test aws_s3_client ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY} )
