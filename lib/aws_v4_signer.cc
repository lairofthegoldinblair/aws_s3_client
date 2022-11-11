#include <iomanip>
#include <set>
#include <sstream>
#include <vector>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim_all.hpp>
#include <boost/log/trivial.hpp>
#include <boost/tokenizer.hpp>
#include "aws_message_digest.hh"
#include "aws_v4_signer.hh"

namespace aws
{
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

  static std::pair<boost::beast::string_view, boost::beast::string_view> split_target(boost::beast::string_view target)
  {
    auto pos = target.find_first_of('?');
    if (pos == boost::beast::string_view::npos) {
      return std::make_pair(target.substr(0), boost::beast::string_view());
    } else {
      return std::make_pair(target.substr(0, pos), target.substr(pos));
    }
  }

  v4_signer::v4_signer(const std::string & secret_key, const std::string & access_key, const std::string & region, const std::string & service)
    :
    secret_key_(secret_key),
    access_key_(access_key),
    region_(region),
    service_(service)
  {
  }

  // See : https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
  void v4_signer::sign_request(boost::beast::http::request<boost::beast::http::string_body> & r, boost::posix_time::ptime now)
  {
    //
    // First we set any x-amz headers since these have to be included in the canonical headers list
    //
  
    // Hex encoded SHA256 Digest of the body
    std::string hashed_payload;
    if (!r.body().empty()) {
      boost::algorithm::hex_lower(message_digest::sha256(r.body()), std::back_inserter(hashed_payload));
    } else {
      // SHA256 of empty
      hashed_payload.assign("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    if(sha256_header_) {
      r.set("x-amz-content-sha256", hashed_payload);
    }
  
    // set date header
    // TODO: Potentially support clock skew correction
    std::string date_header_string = iso_8601_basic_format(now);
    r.set("x-amz-date", date_header_string);

    //
    // Now create the canonical request string, hash and hex encode
    //
  
    // Canonicalize the path segments and query string
    canonicalize(r);
    boost::beast::string_view canonical_path_segments, canonical_query_string;
    std::tie(canonical_path_segments, canonical_query_string) = split_target(r.target());
    std::stringstream canonical_request_str;
    canonical_request_str << r.method_string() << '\n';
    canonical_request_str << canonical_path_segments << '\n';
    // Hmm.... shouldn't the case of no = been caught during canonicalization?
    if (boost::beast::string_view::npos != canonical_query_string.find('=')) {
      canonical_request_str << canonical_query_string.substr(1);
    } else if (canonical_query_string.size() > 1) {
      canonical_request_str << canonical_query_string.substr(1) << '=';
    }
    canonical_request_str << '\n';

    // Now canonicalized headers and list of headers we are signing
    std::map<std::string, std::vector<std::string>> canonical_headers;
    for(const auto & h : r) {
      auto tmp = canonicalize_header(h);
      canonical_headers[tmp.first].push_back(std::move(tmp.second));
    }
    std::stringstream headers_signing_str;
    std::stringstream signed_headers_str;
    bool not_first = false;
    for(const auto & canonical : canonical_headers) {
      if (should_sign(canonical.first)) {
        headers_signing_str << canonical.first << ":" << canonical.second[0];
        for(std::size_t i=1; i<canonical.second.size(); ++i) {
          headers_signing_str << "," << canonical.second[i];
        }
        headers_signing_str << "\n";
        if (not_first) {
          // List of signed headers should not have a trailing ;
          signed_headers_str << ";";
        }
        signed_headers_str << canonical.first;
        not_first = true;
      }
    }
    canonical_request_str << headers_signing_str.str() << '\n';
    canonical_request_str << signed_headers_str.str() << '\n';
    canonical_request_str << hashed_payload;

    BOOST_LOG_TRIVIAL(debug) << "Canonical Request String:\n" << canonical_request_str.str();

    std::string canonical_request_hash;
    boost::algorithm::hex_lower(message_digest::sha256(canonical_request_str.str()), std::back_inserter(canonical_request_hash));

    // Used a few times below
    auto simple_date = simple_date_format(now);

    std::stringstream string_to_sign_str;
    string_to_sign_str << "AWS4-HMAC-SHA256\n" << date_header_string << '\n' << simple_date << "/" << region_ << "/"
                       << service_ << "/" << "aws4_request\n" << canonical_request_hash;

    BOOST_LOG_TRIVIAL(debug) << "String To Sign:\n" << string_to_sign_str.str();

    auto signing_key = generate_signing_key(secret_key_, now, region_, service_);
    std::string key_to_print;
    boost::algorithm::hex_lower(signing_key, std::back_inserter(key_to_print));
    BOOST_LOG_TRIVIAL(debug) << "Key With Which To Sign:\n" << key_to_print;
  

    // HMAC and hex encode
    std::string sig;
    boost::algorithm::hex_lower(hmac::sha256(signing_key, string_to_sign_str.str()), std::back_inserter(sig));
  
    // See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
    std::stringstream auth_header_str;
    auth_header_str << "AWS4-HMAC-SHA256 Credential=" <<  access_key_ << "/" << simple_date
                    << "/" << region_ << "/" << service_ << "/aws4_request, SignedHeaders="
                    << signed_headers_str.str() << ", Signature=" << sig;
    std::string auth_header = auth_header_str.str();
  
    r.set(boost::beast::http::field::authorization, auth_header);
  }

  static std::string ptime_to_string(boost::posix_time::ptime t, const char * fmt)
  {
    // stream takes ownership of the facet.
    std::stringstream ostr;
    boost::posix_time::time_facet * facet = new boost::posix_time::time_facet(fmt);
    ostr.imbue(std::locale(ostr.getloc(), facet));
    ostr << t;
    return ostr.str();
  }

  std::string v4_signer::iso_8601_basic_format(boost::posix_time::ptime t)
  {
    return ptime_to_string(t, "%Y%m%dT%H%M%SZ");
  }

  std::string v4_signer::iso_8601_format(boost::posix_time::ptime t)
  {
    return ptime_to_string(t, "%Y-%m-%dT%H:%M:%SZ");
  }

  std::string v4_signer::simple_date_format(boost::posix_time::ptime t)
  {
    return ptime_to_string(t, "%Y%m%d");
  }

  // Urlencode and put query string parameters in sorted order (lex order of pair (key,value))
  std::string v4_signer::canonicalize_query_string(const std::string & query_string)
  {
    std::set<std::pair<std::string, std::string>> ordered_params;

    BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize_query_string] query string " << query_string;
    typedef boost::tokenizer<boost::char_separator<char> > tokenizer;
    tokenizer key_values(query_string, boost::char_separator<char> ("&"));
    for(tokenizer::iterator key_values_it = key_values.begin(); key_values_it != key_values.end(); ++key_values_it) {
      std::string key_value_pair(*key_values_it);
      BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize_query_string] unparsed key value " << key_value_pair;
      tokenizer key_value(key_value_pair, boost::char_separator<char> ("="));
      tokenizer::iterator key_value_it = key_value.begin();
      std::string key(*key_value_it++);
      if (key_value.end() != key_value_it) {
        BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize_query_string] key: " << key << " value: " << (*key_value_it);
        ordered_params.insert(std::make_pair(urlencode(key, false), urlencode(std::string(*key_value_it), false)));
      } else {
        BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize_query_string] key: " << key;
        ordered_params.insert(std::make_pair(urlencode(key, false), std::string("")));
      }
    }
    std::stringstream ret;
    ret << "?";
    bool not_first = false;
    for(const auto & p : ordered_params)  {
      if (not_first) {
        ret << "&";
      }
      BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize_query_string] building canonicalized query string adding " << p.first << ',' << p.second;
      ret << p.first << "=" << p.second;
      not_first = true;
    }
    BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize_query_string] canonicalized query string " << ret.str();
    return ret.str();
  }

  std::pair<std::string, std::string> v4_signer::canonicalize_header(const boost::beast::http::request<boost::beast::http::string_body>::value_type & h)
  {
    std::string name(h.name_string());
    boost::algorithm::trim_all(name);
    boost::algorithm::to_lower(name);
    std::string value(h.value());
    boost::algorithm::trim_all(value);

    // Handle multiline
    typedef boost::tokenizer<boost::char_separator<char> > tokenizer;
    boost::char_separator<char> sep("\n");
    tokenizer tok(value, sep);
    tokenizer::iterator tokIt = tok.begin();
    if (tokIt == tok.end()) {
      return std::make_pair(std::move(name), "");
    }
    std::string first = boost::algorithm::trim_all_copy(*tokIt++);
    if (tokIt == tok.end()) {
      return std::make_pair(std::move(name), std::move(first));
    }

    std::stringstream sstr;
    sstr << first;
    for(; tokIt != tok.end(); ++tokIt) {
      sstr << " ";
      sstr << boost::algorithm::trim_all_copy(*tokIt);
    }

    // Final trim_all will coalesce adjacent spaces
    return std::make_pair(std::move(name), boost::algorithm::trim_all_copy(sstr.str()));
  }

  // The canonicalization of the uri has two parts:
  // 1) Canonicalize the path segments by urlencoding them (NOT encoding /)
  // 2) Canonicalize the query string by urlencoding each name and value separately,
  // then sorting on name (and value) and reconstituting the query string.
  // See : https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
  void v4_signer::canonicalize(boost::beast::http::request<boost::beast::http::string_body> & http_request)
  {
    boost::beast::string_view path_segments, query_string;
    std::tie(path_segments, query_string) = split_target(http_request.target());
    BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize] Non-canonical target:" << http_request.target();
    BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize] Non-canonical path_segments:" << path_segments;
    BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize] Non-canonical query_string:" << query_string;
    std::stringstream sstr;
    if (path_segments.size() > 0) {
      sstr << urlencode(path_segments, true);
    } else {
      sstr << '/';
    }
    if (boost::beast::string_view() != query_string) {
      sstr << aws::v4_signer::canonicalize_query_string(std::string(query_string.data()+1, query_string.size()-1));
    }
    http_request.target(sstr.str());
    std::tie(path_segments, query_string) = split_target(http_request.target());
    BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize] Canonical target:" << http_request.target();
    BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize] Canonical path_segments:" << path_segments;
    BOOST_LOG_TRIVIAL(debug) << "[aws::v4_signer::canonicalize] Canonical query_string:" << query_string;
  }

  std::string v4_signer::generate_signing_key(const std::string & secret_key, boost::posix_time::ptime t, const std::string& region, const std::string & service)
  {
    auto signing_key = aws::hmac::sha256("AWS4" + secret_key, aws::v4_signer::simple_date_format(t));
    signing_key = aws::hmac::sha256(signing_key, region);
    signing_key = aws::hmac::sha256(signing_key, service);
    signing_key = aws::hmac::sha256(signing_key, "aws4_request");
    return signing_key;
  }
}
