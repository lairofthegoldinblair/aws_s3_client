#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/variant.hpp>
#include <boost/variant/get.hpp>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <set>
#include <string>

#include "aws_message_digest.hh"
#include "aws_v4_signer.hh"

// TODO: For efficiency, break down HMAC function into initialization, cleanup and computation.

std::string url_decode(const char * c, size_t length)
{
  enum DecodeState { PERCENT_DECODE_START, PERCENT_DECODE_x, PERCENT_DECODE_xx };
  std::string mValue;
  DecodeState mDecodeState = PERCENT_DECODE_START;
  char mDecodeChar;
  mValue.reserve(mValue.size() + length);
  const char * end = c + length;
  for(; c != end; ++c) {
    switch(mDecodeState) {
    case PERCENT_DECODE_START:
      switch(*c) {
      case '+':
	mValue.push_back(' ');
	break;
      case '%':
	mDecodeState = PERCENT_DECODE_x;
	break;
      default:
	mValue.push_back(*c);
	break;
      }	
      break;
    case PERCENT_DECODE_x:
      if (*c >= '0' && *c <= '9') {
	mDecodeChar = (char) (*c - '0');
      } else {
	char lower = *c | 0x20;
	if (lower >= 'a' && lower <= 'f') {
	  mDecodeChar = (char) (lower - 'a' + 10);
	} else {
	  mValue.clear();
	  return "";
	}
      }
      mDecodeState = PERCENT_DECODE_xx;
      break;
    case PERCENT_DECODE_xx:
      if (*c >= '0' && *c <= '9') {
	mValue.push_back((char) ((mDecodeChar<<4) + *c - '0'));
      } else {
	char lower = *c | 0x20;
	if (lower >= 'a' && lower <= 'f') {
	  mValue.push_back((char) ((mDecodeChar<<4) + lower - 'a' + 10));
	} else {
	  mValue.clear();
	  return "";
	}
      }
      mDecodeState = PERCENT_DECODE_START;
      break;
    }
  }
  return mValue;
}


namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>


void init_logging(const std::string & level)
{
  if (boost::algorithm::iequals("trace", level)) {
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::trace);
  } else if (boost::algorithm::iequals("debug", level)) {
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::debug);
  } else if (boost::algorithm::iequals("info", level)) {
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);
  } else if (boost::algorithm::iequals("warning", level)) {
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::warning);
  } else if (boost::algorithm::iequals("error", level)) {
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::error);
  }      
}

//------------------------------------------------------------------------------

// Report a failure
void
fail(beast::error_code ec, char const* what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

// Performs an HTTP GET and prints the response
class session : public std::enable_shared_from_this<session>
{
  tcp::resolver resolver_;
  beast::ssl_stream<beast::tcp_stream> stream_;
  beast::flat_buffer buffer_; // (Must persist between reads)
  http::request<http::string_body> req_;
  http::response_parser<http::buffer_body> res_;
  char buf_[1024*1024];
  std::function<void(boost::beast::string_view)> body_sink_;
public:
  // Objects are constructed with a strand to
  // ensure that handlers do not execute concurrently.
  explicit
  session(net::io_context& ioc, ssl::context& ctx,
      std::function<void(boost::beast::string_view)> body_sink)
    : resolver_(net::make_strand(ioc))
    , stream_(net::make_strand(ioc), ctx)
    , body_sink_(body_sink)
  {
  }

  // Start the asynchronous operation
  void
  run(
      char const* host,
      char const* port,
      char const* target,
      int version)
  {
    // Set SNI Hostname (many hosts need this to handshake successfully)
    if(! SSL_set_tlsext_host_name(stream_.native_handle(), host))
      {
        beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
        std::cerr << ec.message() << "\n";
        return;
      }

    // Set up an HTTP GET request message
    req_.version(version);
    req_.method(http::verb::get);
    req_.target(target);
    req_.set(http::field::host, host);
    req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Look up the domain name
    resolver_.async_resolve(
                            host,
                            port,
                            beast::bind_front_handler(
                                                      &session::on_resolve,
                                                      shared_from_this()));
  }

  // Start the asynchronous operation
  void
  run(
      char const* host,
      char const* port,
      const http::request<http::string_body> && req)
  {
    // Set SNI Hostname (many hosts need this to handshake successfully)
    if(! SSL_set_tlsext_host_name(stream_.native_handle(), host))
      {
        beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
        std::cerr << ec.message() << "\n";
        return;
      }

    // Set up an HTTP GET request message
    req_ = std::move(req);

    // Look up the domain name
    resolver_.async_resolve(
                            host,
                            port,
                            beast::bind_front_handler(
                                                      &session::on_resolve,
                                                      shared_from_this()));
  }

  void
  on_resolve(
             beast::error_code ec,
             tcp::resolver::results_type results)
  {
    if(ec)
      return fail(ec, "resolve");

    // BOOST_LOG_TRIVIAL(debug) << 

    // Set a timeout on the operation
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(stream_).async_connect(
                                                   results,
                                                   beast::bind_front_handler(
                                                                             &session::on_connect,
                                                                             shared_from_this()));
  }

  void
  on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
  {
    if(ec)
      return fail(ec, "connect");

    // Perform the SSL handshake
    stream_.async_handshake(
                            ssl::stream_base::client,
                            beast::bind_front_handler(
                                                      &session::on_handshake,
                                                      shared_from_this()));
  }

  void
  on_handshake(beast::error_code ec)
  {
    if(ec)
      return fail(ec, "handshake");

    // Set a timeout on the operation
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Send the HTTP request to the remote host
    http::async_write(stream_, req_,
                      beast::bind_front_handler(
                                                &session::on_write,
                                                shared_from_this()));
  }

  void
  on_write(
           beast::error_code ec,
           std::size_t bytes_transferred)
  {
    boost::ignore_unused(bytes_transferred);

    if(ec)
      return fail(ec, "write");

    // Receive the HTTP response
    http::async_read_header(stream_, buffer_, res_,
                            beast::bind_front_handler(
                                                      &session::on_read_header,
                                                      shared_from_this()));
  }

  void
  on_read_header(
          beast::error_code ec,
          std::size_t bytes_transferred)
  {
    boost::ignore_unused(bytes_transferred);

    if(ec)
      return fail(ec, "read_header");

    // Write the header to standard out
    std::cout << res_.get().base() << std::endl;

    // Set a timeout on the operation
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    res_.get().body().data = buf_;
    res_.get().body().size = sizeof(buf_);
    http::async_read(stream_, buffer_, res_,
                     beast::bind_front_handler(
                                               &session::on_read_body,
                                               shared_from_this()));
  }

  void
  on_read_body(
          beast::error_code ec,
          std::size_t bytes_transferred)
  {
    boost::ignore_unused(bytes_transferred);

    if(ec && ec != http::error::need_buffer)
      return fail(ec, "read");

    // Write the message to body_sink
    boost::beast::string_view vw(&buf_[0], sizeof(buf_) - res_.get().body().size);
    body_sink_(vw);

    // Set a timeout on the operation
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    if (!res_.is_done()) {
      res_.get().body().data = buf_;
      res_.get().body().size = sizeof(buf_);
      http::async_read(stream_, buffer_, res_,
                       beast::bind_front_handler(
                                                 &session::on_read_body,
                                                 shared_from_this()));
    } else {
      // Close up the body_sink
      body_sink_(boost::beast::string_view());
      // Gracefully close the stream
      stream_.async_shutdown(
                             beast::bind_front_handler(
                                                       &session::on_shutdown,
                                                       shared_from_this()));
    }
  }

  void
  on_shutdown(beast::error_code ec)
  {
    if(ec == net::error::eof)
      {
        // Rationale:
        // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
        ec = {};
      }
    if(ec)
      return fail(ec, "shutdown");

    // If we get here then the connection is closed gracefully
  }
};

struct generic_options
{
  std::string host_;
  std::string port_;
  std::string log_level_;
  int32_t version_ = 11;

  void store_generic(const boost::program_options::variables_map & vm)
  {
    host_ = vm["host"].as<std::string>();
    port_ = vm["port"].as<std::string>();
    log_level_ = vm["loglevel"].as<std::string>();
    version_ = boost::algorithm::equals("1.0", vm["version"].as<std::string>()) ? 10 : 11;
  }
};

struct abort_multipart_upload_command_options : public generic_options
{
  std::string bucket_;
  std::string key_;
  std::string upload_id_;
};

struct get_object_command_options : public generic_options
{
  std::string bucket_;
  std::string key_;
};

struct list_buckets_command_options : public generic_options
{
};

struct list_objects_command_options : public generic_options
{
  std::string bucket_;
};

struct list_multipart_uploads_command_options : public generic_options
{
  std::string bucket_;
};

struct put_object_command_options : public generic_options
{
  bool recurse_;
  std::string perms_;
  std::string path_;
};

typedef boost::variant<abort_multipart_upload_command_options, get_object_command_options, list_buckets_command_options, list_objects_command_options, list_multipart_uploads_command_options, put_object_command_options> command;

class extract_generic_command_options : public boost::static_visitor<generic_options &>
{
public:

    template <typename T>
    generic_options & operator()( T & operand ) const
    {
      return *static_cast<generic_options *>(&operand);
    }

  static generic_options & get(command & c)
  {
    extract_generic_command_options v;
    return boost::apply_visitor(v, c);
  }
};

static command parse_options(int argc, const char *argv[])
{
  namespace po = boost::program_options;

  // First get global options and the command
  po::options_description global("Global options");
  global.add_options()
    ("host", po::value<std::string>(), "host to connect to")
    ("port", po::value<std::string>(), "port to connect to")
    ("version", po::value<std::string>()->default_value("1.1"), "HTTP version")
    ("loglevel", po::value<std::string>()->default_value("info"), "level of logging : (trace|debug|info|warning|error)")
    ("command", po::value<std::string>(), "command to execute")
    ("subargs", po::value<std::vector<std::string> >(), "Arguments for command");

  po::positional_options_description pos;
  pos.add("command", 1).
    add("subargs", -1);

  po::variables_map vm;

  po::parsed_options parsed = po::command_line_parser(argc, argv).
    options(global).
    positional(pos).
    allow_unregistered().
    run();

  po::store(parsed, vm);

  // Now parse command specific options
  std::string cmd = vm["command"].as<std::string>();

  if (cmd == "abort-multipart-upload") {
    // ls command has the following options:
    po::options_description ls_desc("abort-multipart-upload options");
    ls_desc.add_options()
      ("bucket", po::value<std::string>(), "Bucket containing upload")
      ("key", po::value<std::string>(), "Key of object being uploaded")
      ("upload-id", po::value<std::string>(), "UploadId of upload to abort")
      ;

    // Collect all the unrecognized options from the first pass. This will include the
    // (positional) command name, so we need to erase that.
    std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
    opts.erase(opts.begin());

    // Parse again...
    po::store(po::command_line_parser(opts).options(ls_desc).run(), vm);

    abort_multipart_upload_command_options ls;
    ls.store_generic(vm);
    ls.bucket_ = vm["bucket"].as<std::string>();
    ls.key_ = vm["key"].as<std::string>();
    ls.upload_id_ = vm["upload-id"].as<std::string>();

    return ls;
  } else if (cmd == "get-object") {
    // ls command has the following options:
    po::options_description ls_desc("abort-multipart-upload options");
    ls_desc.add_options()
      ("bucket", po::value<std::string>(), "Bucket containing object to get")
      ("key", po::value<std::string>(), "Key of object to get")
      ;

    // Collect all the unrecognized options from the first pass. This will include the
    // (positional) command name, so we need to erase that.
    std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
    opts.erase(opts.begin());

    // Parse again...
    po::store(po::command_line_parser(opts).options(ls_desc).run(), vm);

    get_object_command_options ls;
    ls.store_generic(vm);
    ls.bucket_ = vm["bucket"].as<std::string>();
    ls.key_ = vm["key"].as<std::string>();
    return ls;
  } else if (cmd == "list-buckets") {
    list_buckets_command_options ls;
    ls.store_generic(vm);
    return ls;
  } else if (cmd == "list-objects") {
    // ls command has the following options:
    po::options_description ls_desc("list-objects options");
    ls_desc.add_options()
      ("bucket", po::value<std::string>(), "Bucket to list");

    // Collect all the unrecognized options from the first pass. This will include the
    // (positional) command name, so we need to erase that.
    std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
    opts.erase(opts.begin());

    // Parse again...
    po::store(po::command_line_parser(opts).options(ls_desc).run(), vm);

    list_objects_command_options ls;
    ls.store_generic(vm);
    ls.bucket_ = vm["bucket"].as<std::string>();

    return ls;
  } else if (cmd == "list-multipart-uploads") {
    // ls command has the following options:
    po::options_description ls_desc("list-multipart-uploads options");
    ls_desc.add_options()
      ("bucket", po::value<std::string>(), "Bucket to list");

    // Collect all the unrecognized options from the first pass. This will include the
    // (positional) command name, so we need to erase that.
    std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
    opts.erase(opts.begin());

    // Parse again...
    po::store(po::command_line_parser(opts).options(ls_desc).run(), vm);

    // Something similar
    list_multipart_uploads_command_options ls;
    ls.store_generic(vm);
    ls.bucket_ = vm["bucket"].as<std::string>();

    return ls;
  }

  // unrecognised command
  throw po::invalid_option_value(cmd);
}

//------------------------------------------------------------------------------

int main(int argc, const char** argv)
{
  auto args = parse_options(argc, argv);
  auto & generic_args = extract_generic_command_options::get(args);
  
  init_logging(generic_args.log_level_);

  // Get signing key
  std::string secret_key;
  {
    boost::system::error_code ec ;
    std::ifstream fstr("/home/dblair/secret_key.txt");
    std::copy(std::istreambuf_iterator<char>(fstr),
              std::istreambuf_iterator<char>(),
              std::back_inserter(secret_key));
  }
  std::string access_key;
  {
    boost::system::error_code ec ;
    std::ifstream fstr("/home/dblair/access_key.txt");
    std::copy(std::istreambuf_iterator<char>(fstr),
              std::istreambuf_iterator<char>(),
              std::back_inserter(access_key));
  }

  const char * host = generic_args.host_.c_str();
  const char * port = generic_args.port_.c_str();
  const char * target = "/";
  int version = generic_args.version_;
  
    // The io_context is required for all I/O
    net::io_context ioc;

    // The SSL context is required, and holds certificates
    ssl::context ctx{ssl::context::tlsv12_client};

    // Get root certificate
    {
      boost::system::error_code ec ;
      std::ifstream fstr("/etc/ssl/certs/ca-certificates.crt");
      std::string cert;
      std::copy(std::istreambuf_iterator<char>(fstr),
                std::istreambuf_iterator<char>(),
                std::back_inserter(cert));
      ctx.add_certificate_authority(boost::asio::buffer(cert.data(), cert.size()), ec);
      
    }

    // // Set client cert and key
    // ctx.use_certificate_chain_file("/home/dblair/.certs/dblair-testnet.pem");
    // ctx.use_private_key_file("/home/dblair/.certs/dblair-testnet.pem", ssl::context::file_format::pem);

    // Verify the remote server's certificate
    ctx.set_verify_mode(ssl::verify_peer);

    // Launch the asynchronous operation
    // std::make_shared<session>(ioc, ctx)->run(host, port, target, version);
    bool xml_body = false;
    boost::beast::http::request<boost::beast::http::string_body> r;

    if (auto * specific_args = boost::get<abort_multipart_upload_command_options>(&args)) {
      r.version(specific_args->version_);
      r.method(http::verb::delete_);
      r.target((boost::format("/%1%?uploadId=%2%") % specific_args->key_ % specific_args->upload_id_).str());
      r.set(http::field::host, specific_args->bucket_ + "." + specific_args->host_);
      r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
      r.set("amz-sdk-request", "attempt=1");
      xml_body = false;
    } else if (auto * specific_args = boost::get<get_object_command_options>(&args)) {
      // This works for listing buckets
      r.version(specific_args->version_);
      r.method(http::verb::get);
      r.target((boost::format("/%1%") % specific_args->key_).str());
      r.set(http::field::host, specific_args->bucket_ + "." + specific_args->host_);
      r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
      r.set("amz-sdk-request", "attempt=1");
      xml_body = false;
    } else if (auto * specific_args = boost::get<list_buckets_command_options>(&args)) {
      // This works for listing buckets
      r.version(specific_args->version_);
      r.method(http::verb::get);
      r.target("/");
      r.set(http::field::host, specific_args->host_);
      r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
      r.set("amz-sdk-request", "attempt=1");
      xml_body = true;
    } else if (auto * specific_args = boost::get<list_objects_command_options>(&args)) {
      // This works for listing buckets
      r.version(specific_args->version_);
      r.method(http::verb::get);
      r.target("/");
      r.set(http::field::host, specific_args->bucket_ + "." + specific_args->host_);
      r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
      r.set("amz-sdk-request", "attempt=1");
      xml_body = true;
    } else if (auto * specific_args = boost::get<list_multipart_uploads_command_options>(&args)) {
      // This works for listing buckets
      r.version(specific_args->version_);
      r.method(http::verb::get);
      r.target("/?uploads");
      r.set(http::field::host, specific_args->bucket_ + "." + specific_args->host_);
      r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
      r.set("amz-sdk-request", "attempt=1");
      xml_body = true;
    }
    // {
    //   // This works for creating multipart upload
    //   r.version(11);
    //   r.method(http::verb::post);
    //   r.target(target);
    //   r.set(http::field::host, host);
    //   r.set(http::field::content_type, "application/xml");
    //   r.set("x-amz-acl", "private");
    //   r.set("x-amz-api-version", "2006-03-01");
    //   r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
    //   r.set("amz-sdk-request", "attempt=1");
    //   r.content_length(0);
    //   xml_body = true;
    // }
    // {      
    //   // This works for adding a part
    //   // TODO: We need access to the response header to get the etag
    //   std::string body("multipart upload test object contents\n");
    //   r.version(11);
    //   r.method(http::verb::put);
    //   r.target(target);
    //   r.set(http::field::host, host);
    //   r.set(http::field::content_type, "binary/octet-stream");
    //   r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
    //   r.set("amz-sdk-request", "attempt=1");
    //   r.content_length(body.size());
    //   r.body() = std::move(body);
    //   xml_body = true;
    // }
    // {      
    //   // This works for completing a multipart upload      
    //   std::string body("<?xml version=\"1.0\"?>\n<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n<Part>\n<ETag>\"d3931cf77ba23db6427d843fbdf19790\"</ETag>\n<PartNumber>1</PartNumber>\n</Part>\n</CompleteMultipartUpload>\n");
    //   r.version(11);
    //   r.method(http::verb::post);
    //   r.target(target);
    //   r.set(http::field::host, host);
    //   r.set(http::field::content_type, "application/xml");
    //   r.set("x-amz-api-version", "2006-03-01");
    //   r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
    //   r.set("amz-sdk-request", "attempt=1");
    //   r.content_length(body.size());
    //   r.body() = std::move(body);
    //   xml_body = true;
    // }
    // {
    //   // This works for creating a bucket
    //   r.version(11);
    //   r.method(http::verb::put);
    //   r.set("x-amz-acl", "private");
    //   r.target(target);
    //   r.set(http::field::host, host);
    //   r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
    //   r.set("amz-sdk-request", "attempt=1");
    // }
    // {
    //   This works for creating an object
    //   std::string body("test object contents\n");
    //   r.version(11);
    //   r.method(http::verb::put);
    //   r.set("x-amz-meta-foo", "bar");
    //   r.set("x-amz-acl", "private");
    //   r.target(target);
    //   r.set(http::field::host, host);
    //   r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
    //   r.set("amz-sdk-request", "attempt=1");
    //   r.content_length(body.size());
    //   r.body() = std::move(body);
    // }
    // {
    //   // This works for deleting stuff
    //   r.version(11);
    //   r.method(http::verb::delete_);
    //   r.target(target);
    //   r.set(http::field::host, host);
    //   r.set("amz-sdk-invocation-id", boost::uuids::to_string(boost::uuids::random_generator()()));
    //   r.set("amz-sdk-request", "attempt=1");
    // }
    
    aws::v4_signer signer(secret_key, access_key, "us-east-1", "s3");
    // boost::posix_time::ptime ts = boost::posix_time::from_iso_string("20221026T212500");
    // signer.sign_request(r,ts);
    signer.sign_request(r);

    std::stringstream sstr;
    auto response_body_handler = [&sstr](boost::beast::string_view v) {
      if (v.size() > 0) {
        sstr.write(v.data(), v.size());
      }
    };
    std::make_shared<session>(ioc, ctx, response_body_handler)->run(host, port, std::move(r));

    // Run the I/O service. The call will return when
    // the get operation is complete.
    ioc.run();

    std::string response_body = sstr.str();
    std::cout << response_body << std::endl;
    sstr.seekg(0);
    if (xml_body) {
      boost::property_tree::ptree pt;
      boost::property_tree::xml_parser::read_xml(sstr, pt);
      if (pt.begin() != pt.end()) {
        if (boost::algorithm::equals("InitiateMultipartUploadResult", pt.begin()->first)) {
          std::cout << pt.get<std::string>("InitiateMultipartUploadResult.Bucket") << std::endl;
          std::cout << pt.get<std::string>("InitiateMultipartUploadResult.Key") << std::endl;
          std::cout << pt.get<std::string>("InitiateMultipartUploadResult.UploadId") << std::endl;
        } else if (boost::algorithm::equals("ListBucketResult", pt.begin()->first)) {
          std::cout << pt.get<std::string>("ListBucketResult.Name") << std::endl;
          std::cout << pt.get<std::string>("ListBucketResult.Prefix") << std::endl;
          std::cout << pt.get<std::string>("ListBucketResult.MaxKeys") << std::endl;
          std::cout <<  pt.get<std::string>("ListBucketResult.IsTruncated") << std::endl;
          auto contents = pt.get_child("ListBucketResult").equal_range("Contents");
          for(auto it = contents.first; it != contents.second; ++it) {
            boost::property_tree::ptree::value_type & c = *it;
            std::cout << c.second.get<std::string>("Key") << std::endl;
            std::cout << c.second.get<std::string>("LastModified") << std::endl;
            std::cout << c.second.get<std::string>("ETag") << std::endl;
            std::cout << c.second.get<std::string>("Size") << std::endl;
            std::cout << c.second.get<std::string>("StorageClass") << std::endl;
            std::cout << c.second.get<std::string>("Owner.ID") << std::endl;
            std::cout << c.second.get<std::string>("Owner.DisplayName") << std::endl;
            std::cout << c.second.get<std::string>("Type") << std::endl;
            if (boost::algorithm::iequals("true", pt.get<std::string>("ListBucketResult.IsTruncated"))) {
              std::cout <<  pt.get<std::string>("ListBucketResult.NextContinuationToken") << std::endl;
            }
          }
          std::cout << pt.get<std::string>("ListBucketResult.Marker") << std::endl;
        } else if (boost::algorithm::equals("ListAllMyBucketsResult", pt.begin()->first)) {
          std::cout << pt.get<std::string>("ListAllMyBucketsResult.Owner.ID") << std::endl;
          std::cout << pt.get<std::string>("ListAllMyBucketsResult.Owner.DisplayName") << std::endl;
          auto contents = pt.get_child("ListAllMyBucketsResult").equal_range("Buckets");
          for(auto it = contents.first; it != contents.second; ++it) {
            boost::property_tree::ptree::value_type & c = *it;
            std::cout << c.second.get<std::string>("Bucket.Name") << std::endl;
            std::cout << c.second.get<std::string>("Bucket.CreationDate") << std::endl;
          }
        } else if (boost::algorithm::equals("ListMultipartUploadsResult", pt.begin()->first)) {
          std::cout << pt.get<std::string>("ListMultipartUploadsResult.Bucket") << std::endl;
          std::cout << pt.get<std::string>("ListMultipartUploadsResult.NextKeyMarker", "NULL") << std::endl;
          std::cout << pt.get<std::string>("ListMultipartUploadsResult.NextUploadIdMarker", "NULL") << std::endl;
          std::cout <<  pt.get<std::string>("ListMultipartUploadsResult.MaxUploads") << std::endl;
          std::cout <<  pt.get<std::string>("ListMultipartUploadsResult.IsTruncated") << std::endl;
          auto uploads = pt.get_child("ListMultipartUploadsResult").equal_range("Upload");
          for(auto it = uploads.first; it != uploads.second; ++it) {
            boost::property_tree::ptree::value_type & c = *it;
            std::cout << c.second.get<std::string>("Key") << std::endl;
            std::cout << c.second.get<std::string>("UploadId") << std::endl;
            std::cout << c.second.get<std::string>("StorageClass") << std::endl;
            std::cout << c.second.get<std::string>("Initiator.ID") << std::endl;
            std::cout << c.second.get<std::string>("Initiator.DisplayName") << std::endl;
            std::cout << c.second.get<std::string>("Owner.ID") << std::endl;
            std::cout << c.second.get<std::string>("Owner.DisplayName") << std::endl;
            std::cout << c.second.get<std::string>("Initiated") << std::endl;
          }
        }
      }
    }
    
    return EXIT_SUCCESS;
}

