#ifndef __AWS_MESSAGE_DIGEST_HH__
#define __AWS_MESSAGE_DIGEST_HH__

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string>
#include <boost/beast/core/string_type.hpp>

namespace aws
{
  class hmac
  {
  public:
    static std::string sha256(const std::string & key, const std::string & data);
    static std::string sha256(boost::beast::string_view key, boost::beast::string_view data);    
  };
  
  class message_digest
  {
  private:
    EVP_MD_CTX *mdctx_ = nullptr;
    const EVP_MD *md_ = nullptr;  
  public:
    message_digest();
    ~message_digest();
    message_digest & operator<<(const std::string & val);
    std::string str();

    static std::string sha256(const std::string& val);
  };
}

#endif
