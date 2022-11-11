add_library(aws_s3_client aws_v4_signer.cc aws_message_digest.cc aws_request.cc)
target_link_libraries( aws_s3_client ${OPENSSL_LIBRARIES} ${Boost_LOG_LIBRARY} ${LIB_PTHREAD})
