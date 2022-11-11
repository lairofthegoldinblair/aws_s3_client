#include <boost/format.hpp>
#include "aws_message_digest.hh"


aws::message_digest::message_digest()
{
  md_ = EVP_sha256();

  if(!md_) {
    throw std::runtime_error("Could not allocate SHA256 message digest");
  }

  mdctx_ = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx_, md_, nullptr);
}

aws::message_digest & aws::message_digest::operator<<(const std::string & val)
{
  EVP_DigestUpdate(mdctx_, val.data(), val.size());
  return *this;
}

std::string aws::message_digest::str()
{
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  EVP_DigestFinal_ex(mdctx_, md_value, &md_len);
  return std::string((char *) &md_value[0], md_len);
}

aws::message_digest::~message_digest()
{
  EVP_MD_CTX_destroy(mdctx_);
}

std::string aws::message_digest::sha256(const std::string& val)
{
  aws::message_digest d;
  d << val;
  return d.str();
}

std::string aws::hmac::sha256(const std::string & key, const std::string & data)
{
  std::array<unsigned char, EVP_MAX_MD_SIZE> result;
  unsigned int resultlen=0;
  auto ret = HMAC(EVP_sha256(), key.c_str(), key.size(), (const unsigned char *) data.c_str(), data.size(), &result[0], &resultlen);
  if (nullptr == ret) {
    throw std::runtime_error((boost::format("error computing HMAC : resultlen=%1%") % resultlen).str());
  }
  return std::string(&result[0], &result[resultlen]);
}

std::string aws::hmac::sha256(boost::beast::string_view key, boost::beast::string_view data)
{
  std::array<unsigned char, EVP_MAX_MD_SIZE> result;
  unsigned int resultlen=0;
  auto ret = HMAC(EVP_sha256(), &key[0], key.size(), (const unsigned char *) &data[0], data.size(), &result[0], &resultlen);
  if (nullptr == ret) {
    throw std::runtime_error((boost::format("error computing HMAC : resultlen=%1%") % resultlen).str());
  }
  return std::string(&result[0], &result[resultlen]);
}

