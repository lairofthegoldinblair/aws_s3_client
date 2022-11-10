#ifndef __AWS_V4_SIGNER_HH__
#define __AWS_V4_SIGNER_HH__

#include <set>
#include <string>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace aws
{
  class request;

  class v4_signer
  {
  private:
    std::set<std::string> _unsigned_headers;
    std::string secret_key_;
    std::string access_key_;
    std::string region_;
    std::string service_;
    bool sha256_header_=true;
  
    bool should_sign(const std::string & header) const
    {
      // seems to be OK to sign all headers so let's now worry about this for now...
      return _unsigned_headers.end() == _unsigned_headers.find(header);
    }

  public:
    v4_signer(const std::string & secret_key, const std::string & access_key, const std::string & region, const std::string & service);

    void sha256_header(bool val)
    {
      sha256_header_ = val;
    }
  
    void sign_request(boost::beast::http::request<boost::beast::http::string_body> & r, boost::posix_time::ptime now);
    void sign_request(boost::beast::http::request<boost::beast::http::string_body> & r)
    {
      sign_request(r, boost::posix_time::microsec_clock::universal_time());
    }

    static std::string iso_8601_basic_format(boost::posix_time::ptime t);
    static std::string iso_8601_format(boost::posix_time::ptime t);
    static std::string simple_date_format(boost::posix_time::ptime t);
    static std::string canonicalize_query_string(const std::string & query_string);
    static std::pair<std::string, std::string> canonicalize_header(const boost::beast::http::request<boost::beast::http::string_body>::value_type & h);
    static void canonicalize(boost::beast::http::request<boost::beast::http::string_body> & http_request);
    static std::string generate_signing_key(const std::string & secret_key, boost::posix_time::ptime t, const std::string& region, const std::string & service);
  };
}

#endif
