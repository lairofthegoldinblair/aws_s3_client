#include <iomanip>
#include <boost/log/trivial.hpp>
#include "aws_message_digest.hh"
#include "aws_request.hh"
#include "aws_v4_signer.hh"

std::string urlencode(boost::beast::string_view buf, bool skip_slash)
{
  std::stringstream ret;
  ret.fill('0');
  ret << std::hex << std::uppercase;

  for(auto c : buf) {
    // Don't encode unreserved characters in rfc3986 2.3
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || (skip_slash && c == '/')) {
      ret << c;
    } else {
      ret << '%' << std::setw(2) << int((unsigned char)c) << std::setw(0);
    }
  }

  return ret.str();
}

std::string urlencode(const std::string & buf, bool skip_slash)
{
  return urlencode(boost::beast::string_view(buf.data(), buf.size()), skip_slash);
}

void aws::request::target(std::string && val)
{
  boost::beast::string_view tv(val.data(), val.size());
  http_request_.target(tv);
  update_views();
}

std::string aws::request::canonical_uri() const
{
  std::stringstream sstr;
  auto hit = http_request_.find(boost::beast::http::field::host);
  if (http_request_.end() == hit) {
    throw std::runtime_error("aws::request::canonical_uri empty host");
  }
  sstr << (scheme_ == uri_scheme::https ? "https" : "http") << "://" << hit->value();
  if ((uri_scheme::http == scheme_ && 80 != port_) ||
      (uri_scheme::https == scheme_ && 443 != port_)) {
    sstr << ":" << port_;
  }
  if (1 != http_request_.target().size() || '/' != http_request_.target()[0]) {
    sstr << http_request_.target();
  }
  return sstr.str();
}



