#ifndef __AWS_REQUEST_HH__
#define __AWS_REQUEST_HH__

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace aws
{
  enum class uri_scheme { http, https };

  class request
  {
  public:
    typedef boost::beast::http::request<boost::beast::http::string_body> http_request_type;
  private:
    http_request_type http_request_;
    uint16_t port_;
    uri_scheme scheme_;
    boost::beast::string_view path_segments_;
    boost::beast::string_view query_string_;

    void update_views()
    {
      auto pos = http_request_.target().find_first_of('?');
      if (pos == boost::beast::string_view::npos) {
        path_segments_ = http_request_.target().substr(0);
        query_string_ = boost::beast::string_view();
      } else {
        path_segments_ = http_request_.target().substr(0, pos);
        query_string_ = http_request_.target().substr(pos);
      }
    }

  public:

    request() = default;

    request(http_request_type && req)
      :
      http_request_(std::move(req))
    {
      update_views();
    }

    ~request()
    {
    }

    void target(std::string && val);

    http_request_type & http_request()
    {
      return http_request_;
    }

    const http_request_type & http_request() const
    {
      return http_request_;
    }

    boost::beast::string_view query_string() const
    {
      return query_string_;
    }

    boost::beast::string_view path_segments() const
    {
      return path_segments_;
    }

    std::string canonical_uri() const;

  };
}

#endif
