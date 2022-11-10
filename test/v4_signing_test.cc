#include "aws_v4_signer.hh"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>

#define BOOST_TEST_MODULE V4SigningTest
#include <boost/test/unit_test.hpp>

// Set by preprocessor directive
static std::string aws_test_suite_dir = AWS_TEST_SUITE_DIR;

class AwsV4SigningWebsiteTestFixture
{
public:
  // Signer and timestamp for examples on AWS web site (note that examples are incorrect in that they
  // don't put spaces after commas in the Authorization header)
  aws::v4_signer signer;
  boost::posix_time::ptime ts;
  AwsV4SigningWebsiteTestFixture()
    :
    signer("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE", "us-east-1", "s3"),
    ts(boost::posix_time::from_iso_string("20130524T000000"))
  {
  }
};

BOOST_FIXTURE_TEST_CASE(byteRangeGet, AwsV4SigningWebsiteTestFixture)
{
  aws::v4_signer signer("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE", "us-east-1", "s3");
  boost::posix_time::ptime ts = boost::posix_time::from_iso_string("20130524T000000");

  boost::beast::http::request<boost::beast::http::string_body> r;
  r.version(11);
  r.method(boost::beast::http::verb::get);
  r.target("/test.txt");
  r.set(boost::beast::http::field::host, "examplebucket.s3.amazonaws.com");
  r.set(boost::beast::http::field::range, "bytes=0-9");

  signer.sign_request(r, ts);
  auto it = r.find(boost::beast::http::field::authorization);
  BOOST_REQUIRE(r.end() != it);
  BOOST_CHECK(boost::algorithm::equals("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
                                       it->value()));    
}

BOOST_FIXTURE_TEST_CASE(lifecycleGet, AwsV4SigningWebsiteTestFixture)
{
  boost::beast::http::request<boost::beast::http::string_body> r;
  r.version(11);
  r.method(boost::beast::http::verb::get);
  r.target("?lifecycle");
  r.set(boost::beast::http::field::host, "examplebucket.s3.amazonaws.com");

  signer.sign_request(r, ts);
  auto it = r.find(boost::beast::http::field::authorization);
  BOOST_REQUIRE(r.end() != it);
  BOOST_CHECK(boost::algorithm::equals("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
                                       it->value()));
}

BOOST_FIXTURE_TEST_CASE(bucketList, AwsV4SigningWebsiteTestFixture)
{
  boost::beast::http::request<boost::beast::http::string_body> r;
  r.version(11);
  r.method(boost::beast::http::verb::get);
  r.target("?max-keys=2&prefix=J");
  r.set(boost::beast::http::field::host, "examplebucket.s3.amazonaws.com");

  signer.sign_request(r, ts);
  auto it = r.find(boost::beast::http::field::authorization);
  BOOST_REQUIRE(r.end() != it);
  BOOST_CHECK(boost::algorithm::equals("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
                                       it->value()));
}

class AwsV4SigningTestSuiteFixture
{
public:
  // Signer and timestamp for AWS test suite
  aws::v4_signer signer2;
  boost::posix_time::ptime ts2;
  AwsV4SigningTestSuiteFixture()
    :
    signer2("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "AKIDEXAMPLE", "us-east-1", "service"),
    ts2(boost::posix_time::from_iso_string("20150830T123600"))
  {
    signer2.sha256_header(false);    
  }
};

BOOST_FIXTURE_TEST_CASE(multipleHeader, AwsV4SigningTestSuiteFixture)
{
  boost::beast::http::request<boost::beast::http::string_body> r;
  r.version(11);
  r.method(boost::beast::http::verb::get);
  r.target("/");
  r.set(boost::beast::http::field::host, "example.amazonaws.com");
  r.set("My-Header1", "value1");
  r.set("My-Header2", "\"a   b   c\"");

  signer2.sign_request(r, ts2);
  auto it = r.find(boost::beast::http::field::authorization);
  BOOST_REQUIRE(r.end() != it);
  BOOST_CHECK(boost::algorithm::equals("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;my-header2;x-amz-date, Signature=acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
                                       it->value()));
}

BOOST_FIXTURE_TEST_CASE(vanillaGet, AwsV4SigningTestSuiteFixture)
{
  boost::beast::http::request<boost::beast::http::string_body> r;
  r.version(11);
  r.method(boost::beast::http::verb::get);
  r.target("/");
  r.set(boost::beast::http::field::host, "example.amazonaws.com");
  r.set("X-Amz-Date", "20150830T123600Z");

  signer2.sign_request(r, ts2);
  auto it = r.find(boost::beast::http::field::authorization);
  BOOST_REQUIRE(r.end() != it);
  BOOST_CHECK(boost::algorithm::equals("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
                                       it->value()));
  //   if (r.end() != it) {
  //     std::cout << "Authorization: " << it->value() << std::endl;
  //     if (!boost::algorithm::equals("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
  //                                   it->value())) {
  //       std::cerr << "Test failed" << std::endl;
  //     } else {
  //       std::cout << "Test succeeded" << std::endl;
  //     }
  //   } else {
  //     std::cerr << "No auth header generated" << std::endl;
  //   }
  // }
}

/** Read a message from a `std::istream`.

    This function attempts to parse a complete HTTP/1 message from the stream.

    @param is The `std::istream` to read from.

    @param buffer The buffer to use.

    @param msg The message to store the result.

    @param ec Set to the error, if any occurred.
*/
template<class Allocator, bool isRequest, class Body>
void read_istream(std::istream& is,
                  boost::beast::basic_flat_buffer<Allocator>& buffer,
                  boost::beast::http::message<isRequest, Body, boost::beast::http::fields>& msg,
                  boost::beast::error_code& ec)
{
    // Create the message parser
    //
    // Arguments passed to the parser's constructor are
    // forwarded to the message constructor. Here, we use
    // a move construction in case the caller has constructed
    // their message in a non-default way.
    //
  boost::beast::http::parser<isRequest, Body> p{std::move(msg)};

    do
    {
        // Extract whatever characters are presently available in the istream
        if(is.rdbuf()->in_avail() > 0)
        {
            // Get a mutable buffer sequence for writing
            auto const b = buffer.prepare(
                static_cast<std::size_t>(is.rdbuf()->in_avail()));

            // Now get everything we can from the istream
            buffer.commit(static_cast<std::size_t>(is.readsome(
                reinterpret_cast<char*>(b.data()), b.size())));
        }
        else if(buffer.size() == 0)
        {
            // Our buffer is empty and we need more characters, 
            // see if we've reached the end of file on the istream
            if(! is.eof())
            {
                // Get a mutable buffer sequence for writing
                auto const b = buffer.prepare(1024);

                // Try to get more from the istream. This might block.
                is.read(reinterpret_cast<char*>(b.data()), b.size());

                // If an error occurs on the istream then return it to the caller.
                if(is.fail() && ! is.eof())
                {
                    // We'll just re-use io_error since std::istream has no error_code interface.
                  ec = boost::beast::errc::make_error_code(boost::beast::errc::io_error);
                    return;
                }

                // Commit the characters we got to the buffer.
                buffer.commit(static_cast<std::size_t>(is.gcount()));
            }
            else
            {
                // Inform the parser that we've reached the end of the istream.
                p.put_eof(ec);
                if(ec)
                    return;
                break;
            }
        }

        // Write the data to the parser
        auto const bytes_used = p.put(buffer.data(), ec);

        // This error means that the parser needs additional octets.
        if(ec == boost::beast::http::error::need_more)
            ec = {};
        if(ec)
            return;

        // Consume the buffer octets that were actually parsed.
        buffer.consume(bytes_used);
    }
    while(! p.is_done());

    // Transfer ownership of the message container in the parser to the caller.
    msg = p.release();
}

BOOST_FIXTURE_TEST_CASE(allTests, AwsV4SigningTestSuiteFixture)
{
  std::cout << aws_test_suite_dir << std::endl;
    boost::filesystem::directory_iterator dir(aws_test_suite_dir);
    boost::filesystem::directory_iterator end;
    for(; dir != end; ++dir) {
      if (boost::filesystem::directory_file != dir->status().type()) {
        continue;
      }
      auto dir_path = dir->path();
      // BOOST_LOG_TRIVIAL(info) << "Running test at : " << dir_path;
      BOOST_TEST_MESSAGE("Running test at : " << dir_path);

      // Get the dir name of the test
      boost::filesystem::path test = *dir_path.rbegin();
      // There seem to be some broken AWS test cases!!!!
      if (boost::algorithm::equals("get-header-value-multiline", test.c_str())
          || boost::algorithm::equals("post-x-www-form-urlencoded", test.c_str())
          || boost::algorithm::equals("post-x-www-form-urlencoded-parameters", test.c_str())
          ) {
        continue;
      }
      // if (!boost::algorithm::equals("post-x-www-form-urlencoded-parameters", test.c_str())) {
      //   continue;
      // }
      if(!boost::filesystem::exists(dir_path / test.replace_extension(".req"))) {
        continue;
      }    
      // BOOST_LOG_TRIVIAL(info) << "Test : " << test;
      // BOOST_LOG_TRIVIAL(info) << "Test Request : " << (dir_path / test.replace_extension(".req"));
      // BOOST_LOG_TRIVIAL(info) << "Test Response : " << (dir_path / test.replace_extension(".authz"));
      // Amazon test requests don't use \r\n!
      std::stringstream converted;
      {
        boost::filesystem::ifstream fstr(dir_path / test.replace_extension(".req"));
        BOOST_ASSERT(!!fstr);
        // std::ifstream fstr("/home/dblair/thirdparty/aws-sig-v4-test-suite/raw/aws-sig-v4-test-suite/get-vanilla/get-vanilla.req");
        bool end_headers = false;
        char c;
        std::size_t chars_in_line=0;
        while(fstr.get(c)) {
          if (end_headers || c != '\n') {
            converted << c;
            chars_in_line += 1;
          } else {
            converted << "\r\n";
            if (0 == chars_in_line) {
              end_headers = true;
            } else {
              chars_in_line = 0;
            }
          }
        }
        if (!end_headers) {
          if (chars_in_line>0) {
            // A header line without EOL
            converted << "\r\n";
          }
          // Needed to indicate end of headers
          converted << "\r\n";
        }
      }
      converted.seekg(0);
      auto tmp = converted.str();
      boost::beast::http::request<boost::beast::http::string_body> req;
      boost::beast::flat_buffer buf;
      boost::beast::error_code ec;
      read_istream(converted, buf, req, ec);
      boost::beast::http::request<boost::beast::http::string_body> r(std::move(req));
      signer2.sign_request(r, ts2);
      auto it = r.find(boost::beast::http::field::authorization);
      BOOST_REQUIRE(r.end() != it);
      std::string expected;
      boost::filesystem::ifstream fstr(dir_path / test.replace_extension(".authz"));
      // std::ifstream fstr("/home/dblair/thirdparty/aws-sig-v4-test-suite/raw/aws-sig-v4-test-suite/get-vanilla/get-vanilla.authz");
      std::copy(std::istreambuf_iterator<char>(fstr),
                std::istreambuf_iterator<char>(),
                std::back_inserter(expected));
      BOOST_CHECK(boost::algorithm::equals(expected, it->value()));
      // if (r.end() != it) {
      //   std::string expected;
      //   boost::filesystem::ifstream fstr(dir_path / test.replace_extension(".authz"));
      //   // std::ifstream fstr("/home/dblair/thirdparty/aws-sig-v4-test-suite/raw/aws-sig-v4-test-suite/get-vanilla/get-vanilla.authz");
      //   std::copy(std::istreambuf_iterator<char>(fstr),
      //             std::istreambuf_iterator<char>(),
      //             std::back_inserter(expected));
      //   std::cout << "Authorization: " << it->value() << std::endl;
      //   if (!boost::algorithm::equals(expected, it->value())) {
      //     std::cerr << "Test failed" << std::endl;
      //   } else {
      //     std::cout << "Test succeeded" << std::endl;
      //   }
      // } else {
      //   std::cerr << "No auth header generated" << std::endl;
      // }
    }
}
