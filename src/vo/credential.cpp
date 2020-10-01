#include <numeric>
#include <pichi/common/asserts.hpp>
#include <pichi/common/literals.hpp>
#include <pichi/vo/credential.hpp>
#include <pichi/vo/keys.hpp>
#include <pichi/vo/messages.hpp>
#include <pichi/vo/parse.hpp>
#include <pichi/vo/to_json.hpp>

using namespace std;
namespace json = rapidjson;
using Allocator = json::Document::AllocatorType;

namespace pichi::vo {

template <typename R, typename F> R parseArray(json::Value const& v, F&& f)
{
  assertTrue(v.IsArray(), PichiError::BAD_JSON, msg::ARY_TYPE_ERROR);
  auto&& all = v.GetArray();
  assertFalse(all.Empty(), PichiError::BAD_JSON, msg::ARY_SIZE_ERROR);
  return accumulate(begin(all), end(all), R{}, forward<F>(f));
}

template <typename Credential, typename Converter>
json::Value toJson(Credential const& cred, Converter&& convert, Allocator& alloc)
{
  assertFalse(cred.credential_.empty());
  auto ret = json::Value{json::kArrayType};
  for (auto&& item : cred.credential_) ret.PushBack(convert(item, alloc), alloc);
  return ret;
}

namespace up {

static auto toJson(pair<string, string> const& p, Allocator& alloc)
{
  auto&& [username, password] = p;
  auto item = json::Value{json::kObjectType};
  item.AddMember(credential::USERNAME, vo::toJson(username, alloc), alloc);
  item.AddMember(credential::PASSWORD, vo::toJson(password, alloc), alloc);
  return item;
}

}  // namespace up

template <> up::IngressCredential parse(json::Value const& v)
{
  return {parseArray<unordered_map<string, string>>(v, [](auto&& sum, auto&& item) {
    assertTrue(item.IsObject(), PichiError::BAD_JSON, msg::OBJ_TYPE_ERROR);
    assertTrue(item.HasMember(credential::USERNAME), PichiError::BAD_JSON, msg::MISSING_UN_FIELD);
    assertTrue(item.HasMember(credential::PASSWORD), PichiError::BAD_JSON, msg::MISSING_PW_FIELD);
    auto [_, inserted] = sum.insert_or_assign(parse<string>(item[credential::USERNAME]),
                                              parse<string>(item[credential::PASSWORD]));
    assertTrue(inserted, PichiError::SEMANTIC_ERROR, msg::DUPLICATED_ITEMS);
    return move(sum);
  })};
}

json::Value toJson(up::IngressCredential const& cred, Allocator& alloc)
{
  return toJson(cred, up::toJson, alloc);
}

template <> up::EgressCredential parse(json::Value const& v)
{
  assertTrue(v.IsObject(), PichiError::BAD_JSON, msg::ARY_TYPE_ERROR);
  assertTrue(v.HasMember(credential::USERNAME), PichiError::BAD_JSON, msg::MISSING_UN_FIELD);
  assertTrue(v.HasMember(credential::PASSWORD), PichiError::BAD_JSON, msg::MISSING_PW_FIELD);
  return {
      make_pair(parse<string>(v[credential::USERNAME]), parse<string>(v[credential::PASSWORD]))};
}

json::Value toJson(up::EgressCredential const& cred, Allocator& alloc)
{
  return up::toJson(cred.credential_, alloc);
}

namespace trojan {

static auto toJson(string_view pw, Allocator& alloc)
{
  auto ret = json::Value{json::kObjectType};
  ret.AddMember(credential::PASSWORD, vo::toJson(pw, alloc), alloc);
  return ret;
}

}  // namespace trojan

template <> trojan::IngressCredential parse(json::Value const& v)
{
  return {parseArray<unordered_set<string>>(v, [](auto&& sum, auto&& item) {
    assertTrue(item.IsObject(), PichiError::BAD_JSON, msg::OBJ_TYPE_ERROR);
    assertTrue(item.HasMember(credential::PASSWORD), PichiError::BAD_JSON, msg::MISSING_PW_FIELD);
    auto [_, inserted] = sum.insert(parse<string>(item[credential::PASSWORD]));
    assertTrue(inserted, PichiError::SEMANTIC_ERROR, msg::DUPLICATED_ITEMS);
    return move(sum);
  })};
}

json::Value toJson(trojan::IngressCredential const& cred, Allocator& alloc)
{
  return toJson(cred, trojan::toJson, alloc);
}

template <> trojan::EgressCredential parse(json::Value const& v)
{
  assertTrue(v.IsObject(), PichiError::BAD_JSON, msg::OBJ_TYPE_ERROR);
  assertTrue(v.HasMember(credential::PASSWORD), PichiError::BAD_JSON, msg::MISSING_PW_FIELD);
  return {parse<string>(v[credential::PASSWORD])};
}

json::Value toJson(trojan::EgressCredential const& cred, Allocator& alloc)
{
  return trojan::toJson(cred.credential_, alloc);
}

namespace vmess {

static auto toJson(pair<string, uint16_t> const& p, Allocator& alloc)
{
  auto&& [uuid, alterId] = p;
  auto item = json::Value{json::kObjectType};
  item.AddMember(credential::UUID, vo::toJson(uuid, alloc), alloc);
  item.AddMember(credential::ALTER_ID, json::Value(alterId), alloc);
  return item;
}

}  // namespace vmess

template <> vmess::IngressCredential parse(json::Value const& v)
{
  return {parseArray<unordered_map<string, uint16_t>>(v, [](auto&& sum, auto&& item) {
    assertTrue(item.IsObject(), PichiError::BAD_JSON, msg::OBJ_TYPE_ERROR);
    assertTrue(item.HasMember(credential::UUID), PichiError::BAD_JSON, msg::MISSING_UUID_FIELD);
    auto [_, inserted] = sum.insert_or_assign(
        parse<string>(item[credential::UUID]),
        item.HasMember(credential::ALTER_ID) ? parse<uint16_t>(item[credential::ALTER_ID]) : 0_u16);
    assertTrue(inserted, PichiError::SEMANTIC_ERROR, msg::DUPLICATED_ITEMS);
    return move(sum);
  })};
}

json::Value toJson(vmess::IngressCredential const& cred, Allocator& alloc)
{
  return toJson(cred, vmess::toJson, alloc);
}

template <> vmess::EgressCredential parse(json::Value const& v)
{
  assertTrue(v.IsObject(), PichiError::BAD_JSON, msg::OBJ_TYPE_ERROR);
  assertTrue(v.HasMember(credential::UUID), PichiError::BAD_JSON, msg::MISSING_UUID_FIELD);
  auto ret =
      vmess::EgressCredential{parse<string>(v[credential::UUID]), 0_u16, VMessSecurity::AUTO};
  if (v.HasMember(credential::ALTER_ID)) ret.alter_id_ = parse<uint16_t>(v[credential::ALTER_ID]);
  if (v.HasMember(credential::SECURITY))
    ret.security_ = parse<VMessSecurity>(v[credential::SECURITY]);
  return ret;
}

json::Value toJson(vmess::EgressCredential const& cred, Allocator& alloc)
{
  auto ret = json::Value{json::kObjectType};
  ret.AddMember(credential::UUID, toJson(cred.uuid_, alloc), alloc);
  ret.AddMember(credential::ALTER_ID, json::Value{cred.alter_id_}, alloc);
  ret.AddMember(credential::SECURITY, toJson(cred.security_, alloc), alloc);
  return ret;
}

bool operator==(up::IngressCredential const& lhs, up::IngressCredential const& rhs)
{
  return lhs.credential_ == rhs.credential_;
}

bool operator==(up::EgressCredential const& lhs, up::EgressCredential const& rhs)
{
  return lhs.credential_ == rhs.credential_;
}

bool operator==(trojan::IngressCredential const& lhs, trojan::IngressCredential const& rhs)
{
  return lhs.credential_ == rhs.credential_;
}

bool operator==(trojan::EgressCredential const& lhs, trojan::EgressCredential const& rhs)
{
  return lhs.credential_ == rhs.credential_;
}

bool operator==(vmess::IngressCredential const& lhs, vmess::IngressCredential const& rhs)
{
  return lhs.credential_ == rhs.credential_;
}

bool operator==(vmess::EgressCredential const& lhs, vmess::EgressCredential const& rhs)
{
  return lhs.uuid_ == rhs.uuid_ && lhs.alter_id_ == rhs.alter_id_ && lhs.security_ == rhs.security_;
}

}  // namespace pichi::vo
