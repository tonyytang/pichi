#include "utils.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/test/unit_test.hpp>
#include <pichi/common/literals.hpp>
#include <pichi/vo/egress.hpp>
#include <pichi/vo/ingress.hpp>
#include <pichi/vo/keys.hpp>
#include <pichi/vo/to_json.hpp>
#include <sodium/utils.h>
#include <string.h>

using namespace std;
using namespace rapidjson;

namespace pichi::unit_test {

static auto doc = Document{};
Document::AllocatorType& alloc = doc.GetAllocator();

static boost::asio::io_context io;
static boost::asio::detail::Pull* pPull = nullptr;
static boost::asio::detail::Push* pPush = nullptr;
static boost::asio::detail::YieldState* pState = nullptr;
static auto const DEFAULT_ENDPOINT = makeEndpoint("localhost", 80_u16);
boost::asio::yield_context gYield = {io.get_executor(), *pState, *pPush, *pPull};

vector<uint8_t> str2vec(string_view s) { return {cbegin(s), cend(s)}; }

vector<uint8_t> hex2bin(string_view hex)
{
  auto v = vector<uint8_t>(hex.size() / 2, 0);
  sodium_hex2bin(v.data(), v.size(), hex.data(), hex.size(), nullptr, nullptr, nullptr);
  return v;
}

vo::Ingress defaultIngressVO(AdapterType type)
{
  auto vo = vo::Ingress{};
  vo.type_ = type;
  vo.bind_.emplace_back(DEFAULT_ENDPOINT);
  switch (type) {
  case AdapterType::HTTP:
  case AdapterType::SOCKS5:
    vo.tls_ = false;
    break;
  case AdapterType::SS:
    vo.method_ = CryptoMethod::RC4_MD5;
    vo.password_ = ph;
    break;
  case AdapterType::TUNNEL:
    vo.destinations_ = {DEFAULT_ENDPOINT};
    vo.balance_ = BalanceType::RANDOM;
    break;
  case AdapterType::TROJAN:
    vo.passwords_ = {ph};
    vo.remote_ = DEFAULT_ENDPOINT;
    vo.certFile_ = ph;
    vo.keyFile_ = ph;
    break;
  default:
    BOOST_ERROR("Invalid type");
    break;
  }
  return vo;
}

Value defaultIngressJson(AdapterType type)
{
  auto dst = Value{};
  dst.SetObject();
  dst.AddMember("localhost", 80, alloc);
  auto v = Value{kObjectType};
  v.AddMember(vo::ingress::BIND, Value{kArrayType}, alloc);
  v[vo::ingress::BIND].PushBack(vo::toJson(DEFAULT_ENDPOINT, alloc), alloc);
  switch (type) {
  case AdapterType::HTTP:
    v.AddMember(vo::ingress::TYPE, vo::type::HTTP, alloc);
    v.AddMember(vo::ingress::TLS, false, alloc);
    break;
  case AdapterType::SOCKS5:
    v.AddMember(vo::ingress::TYPE, vo::type::SOCKS5, alloc);
    v.AddMember(vo::ingress::TLS, false, alloc);
    break;
  case AdapterType::SS:
    v.AddMember(vo::ingress::TYPE, vo::type::SS, alloc);
    v.AddMember(vo::ingress::METHOD, vo::method::RC4_MD5, alloc);
    v.AddMember(vo::ingress::PASSWORD, ph, alloc);
    break;
  case AdapterType::TUNNEL:
    v.AddMember(vo::ingress::TYPE, vo::type::TUNNEL, alloc);
    v.AddMember(vo::ingress::DESTINATIONS, dst, alloc);
    v.AddMember(vo::ingress::BALANCE, vo::balance::RANDOM, alloc);
    break;
  case AdapterType::TROJAN:
    v.AddMember("type", "trojan", alloc);
    v.AddMember("passwords", Value{}.SetArray().PushBack(ph, alloc), alloc);
    v.AddMember("remote_host", "localhost", alloc);
    v.AddMember("remote_port", 80, alloc);
    v.AddMember("cert_file", ph, alloc);
    v.AddMember("key_file", ph, alloc);
    break;
  default:
    BOOST_ERROR("Invalid type");
    break;
  }
  return v;
}

vo::Egress defaultEgressVO(AdapterType type)
{
  auto vo = vo::Egress{};
  vo.type_ = type;
  switch (type) {
  case AdapterType::DIRECT:
    break;
  case AdapterType::REJECT:
    vo.mode_ = DelayMode::FIXED;
    vo.delay_ = 0_u16;
    break;
  case AdapterType::SS:
    vo.method_ = CryptoMethod::RC4_MD5;
    vo.password_ = ph;
    vo.host_ = ph;
    vo.port_ = 1_u8;
    break;
  case AdapterType::HTTP:
  case AdapterType::SOCKS5:
    vo.host_ = ph;
    vo.port_ = 1_u8;
    vo.tls_ = false;
    break;
  case AdapterType::TROJAN:
    vo.host_ = ph;
    vo.port_ = 1_u8;
    vo.password_ = ph;
    vo.insecure_ = false;
    break;
  default:
    BOOST_ERROR("Invalid type");
    break;
  }
  return vo;
}

Value defaultEgressJson(AdapterType type)
{
  auto v = Value{};
  v.SetObject();
  if (type != AdapterType::DIRECT && type != AdapterType::REJECT) {
    v.AddMember(vo::egress::HOST, ph, alloc);
    v.AddMember(vo::egress::PORT, 1, alloc);
  }
  switch (type) {
  case AdapterType::DIRECT:
    v.AddMember(vo::egress::TYPE, vo::type::DIRECT, alloc);
    break;
  case AdapterType::REJECT:
    v.AddMember(vo::egress::TYPE, vo::type::REJECT, alloc);
    v.AddMember(vo::egress::MODE, vo::delay::FIXED, alloc);
    v.AddMember(vo::egress::DELAY, 0, alloc);
    break;
  case AdapterType::HTTP:
    v.AddMember(vo::egress::TYPE, vo::type::HTTP, alloc);
    v.AddMember(vo::egress::TLS, false, alloc);
    break;
  case AdapterType::SOCKS5:
    v.AddMember(vo::egress::TYPE, vo::type::SOCKS5, alloc);
    v.AddMember(vo::egress::TLS, false, alloc);
    break;
  case AdapterType::SS:
    v.AddMember(vo::egress::TYPE, vo::type::SS, alloc);
    v.AddMember(vo::egress::METHOD, vo::method::RC4_MD5, alloc);
    v.AddMember(vo::egress::PASSWORD, ph, alloc);
    break;
  case AdapterType::TROJAN:
    v.AddMember("type", "trojan", alloc);
    v.AddMember("password", ph, alloc);
    break;
  default:
    BOOST_ERROR("Invalid type");
    break;
  }
  return v;
}

}  // namespace pichi::unit_test
