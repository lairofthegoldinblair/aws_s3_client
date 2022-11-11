add_executable(aws_client aws_s3_client.cc)
set_target_properties( aws_client PROPERTIES OUTPUT_NAME "aws-s3-client")
target_link_libraries( aws_client aws_s3_client ${Boost_DATETIME_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY})


