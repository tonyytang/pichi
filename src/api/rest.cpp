#include <pichi/common/config.hpp>
// Include config.hpp first
#include <pichi/api/egress_manager.hpp>
#include <pichi/api/ingress_manager.hpp>
#include <pichi/api/rest.hpp>
#include <pichi/api/router.hpp>
#include <pichi/vo/error.hpp>
#include <pichi/vo/parse.hpp>
#include <pichi/vo/to_json.hpp>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <sstream>

using namespace std;
using boost::beast::http;
namespace asio = boost::asio;
namespace http = boost::beast::http;
namespace json = rapidjson;
namespace sys = boost::system;

namespace pichi::api {

template <class TBody>
response<TBody>*
DelegateHandler<TBody>::handleRequest(request<TBody> const * request)
{
    if (inner) {
        return inner->handleRequest(request);
    }

    return NULL;
}

template <class TBody>
response<TBody>*
CorsDelegateHandler<TBody>::handleRequest(request<TBody> const * request)
{
    if (request->method() == verb::options) {
        auto response = new ::response<TBody>{status::no_content};
        response.set("Access-Control-Allow-Methods", "*");
        response.set("Access-Control-Allow-Headers", "*");
        
        return response;
    }

    return DelegateHandler<TBody>::handlerRequest(request);
}

template <class TBody>
response<TBody>*
Route<TBody>::handleRequestIfMatches(request<TBody> const * request)
{
  auto m = cmatch{};
  auto target = request->target();
  if (request->method() == get<0>(this) &&
    regex_match(target.data(), target.data() + target.size(), m, get<1>(this))) {
    return invoke(get<2>(*this), request, m);
  }
  
  return NULL;
}

template <class TBody>
Config<TBody>::Config()
  : _handler(new Config<TBody>::RouteRequestHandler(_routes))
{
}

template <class TBody>
Config<TBody>::~Config()
{
  while (_handler) {
    auto current = _handler;
    _handler = _handler->inner;
    delete current;
  }
}

template <class TBody>
void
Config<TBody>::addHandler(DelegateHandler<TBody> const * handler)
{
  handler->inner = _handler;
  _handler = handler;
}

template <class TBody>
void
Config<TBody>::addRoute(Route<TBody> const & route)
{
  _routes.push(route);
}

template <class TBody>
response<TBody>*
Config<TBody>::handleRequest(request<TBody> const * request)
{
  return _handler->handle(request);
}

template <class TBody>
response<TBody>*
Config<TBody>::RouteRequestHandler::handleRequest(request<TBody> const * request)
{
  for (auto route = cbegin(_routes); route != cend(_routes); route++) {
    if (auto response = route.handleRequestIfMatches(request))
        return response;
  }
  return response<TBody>{status::bad_request};
}

static auto const INGRESS_REGEX = regex{"^/ingresses/?([?#].*)?$"};
static auto const INGRESS_NAME_REGEX = regex{"^/ingresses/([^?#/]+)/?([?#].*)?$"};
static auto const EGRESS_REGEX = regex{"^/egresses/?([?#].*)?$"};
static auto const EGRESS_NAME_REGEX = regex{"^/egresses/([^?#]+)/?([?#].*)?$"};
static auto const RULE_REGEX = regex{"^/rules/?([?#].*)?$"};
static auto const RULE_NAME_REGEX = regex{"^/rules/([^?#]+)/?([?#].*)?$"};
static auto const ROUTE_REGEX = regex{"^/route/?([?#].*)?$"};
static auto const CLEAR = regex{"^/clear$"};

static auto genResp(http::status status) { return Rest::Response{status, 11}; }

template <typename... Args> static auto genResp(http::status status, Args&&... args)
{
  auto alloc = json::Document::AllocatorType{};
  auto json = toJson(forward<Args>(args)..., alloc);
  auto buf = json::StringBuffer{};
  auto writer = json::Writer<json::StringBuffer>{buf};
  json.Accept(writer);

  auto ret = genResp(status);
  ret.set(http::field::content_type, "application/json");
  ret.body() = buf.GetString();
  return ret;
}

static bool matching(boost::string_view s, regex const& re, cmatch& r)
{
  return regex_match(s.data(), s.data() + s.size(), r, re);
}

template <typename Manager> static auto getVO(Manager const& manager)
{
  return genResp(http::status::ok, begin(manager), end(manager));
}

template <typename Manager>
static auto putVO(Rest::Request const& req, cmatch const& mr, Manager& manager)
{
  manager.update(mr[1].str(), vo::parse<typename Manager::VO>(req.body()));
  return genResp(http::status::no_content);
}

template <typename Manager> static auto delVO(cmatch const& mr, Manager& manager)
{
  manager.erase(mr[1].str());
  return genResp(http::status::no_content);
}

static auto options(initializer_list<http::verb>&& verbs)
{
  auto oss = ostringstream{};
  auto first = cbegin(verbs);
  if (first != cend(verbs)) oss << *first++;
  for_each(first, cend(verbs), [&oss](auto verb) { oss << "," << verb; });

  auto resp = genResp(http::status::no_content);
  resp.set("Access-Control-Allow-Methods", oss.str());
  return resp;
}

static http::status e2c(PichiError e)
{
  switch (e) {
  case PichiError::RES_IN_USE:
    return http::status::forbidden;
  case PichiError::BAD_JSON:
    return http::status::bad_request;
  case PichiError::SEMANTIC_ERROR:
    return http::status::unprocessable_entity;
  default:
    return http::status::internal_server_error;
  }
}

static http::status e2c(sys::error_code e)
{
  return e == asio::error::address_in_use ? http::status::locked
                                          : http::status::internal_server_error;
}

Rest::Rest(IngressManager& ingresses, EgressManager& egresses, Router& router)
  : apis_{
        make_tuple(http::verb::get, INGRESS_REGEX,
                   [&](auto&&, auto&&) { return getVO(ingresses); }),
        make_tuple(http::verb::options, INGRESS_REGEX,
                   [](auto&&, auto&&) {
                     return options({http::verb::get, http::verb::options});
                   }),
        make_tuple(http::verb::put, INGRESS_NAME_REGEX,
                   [&](auto&& r, auto&& mr) { return putVO(r, mr, ingresses); }),
        make_tuple(http::verb::delete_, INGRESS_NAME_REGEX,
                   [&](auto&&, auto&& mr) { return delVO(mr, ingresses); }),
        make_tuple(http::verb::options, INGRESS_NAME_REGEX,
                   [](auto&&, auto&&) {
                     return options({http::verb::put, http::verb::delete_, http::verb::options});
                   }),
        make_tuple(http::verb::get, EGRESS_REGEX, [&](auto&&, auto&&) { return getVO(egresses); }),
        make_tuple(http::verb::options, EGRESS_REGEX,
                   [](auto&&, auto&&) {
                     return options({http::verb::get, http::verb::options});
                   }),
        make_tuple(http::verb::put, EGRESS_NAME_REGEX,
                   [&](auto&& r, auto&& mr) { return putVO(r, mr, egresses); }),
        make_tuple(http::verb::delete_, EGRESS_NAME_REGEX,
                   [&](auto&&, auto&& mr) {
                     assertFalse(router.isUsed(mr[1].str()), PichiError::RES_IN_USE);
                     return delVO(mr, egresses);
                   }),
        make_tuple(http::verb::options, EGRESS_NAME_REGEX,
                   [](auto&&, auto&&) {
                     return options({http::verb::put, http::verb::delete_, http::verb::options});
                   }),
        make_tuple(http::verb::get, RULE_REGEX, [&](auto&&, auto&&) { return getVO(router); }),
        make_tuple(http::verb::options, RULE_REGEX,
                   [](auto&&, auto&&) {
                     return options({http::verb::get, http::verb::options});
                   }),
        make_tuple(http::verb::put, RULE_NAME_REGEX,
                   [&](auto&& r, auto&& mr) { return putVO(r, mr, router); }),
        make_tuple(http::verb::delete_, RULE_NAME_REGEX,
                   [&](auto&&, auto&& mr) { return delVO(mr, router); }),
        make_tuple(http::verb::options, RULE_NAME_REGEX,
                   [](auto&&, auto&&) {
                     return options({http::verb::put, http::verb::delete_, http::verb::options});
                   }),
        make_tuple(http::verb::get, ROUTE_REGEX,
                   [&](auto&&, auto&&) { return genResp(http::status::ok, router.getRoute()); }),
        make_tuple(http::verb::put, ROUTE_REGEX,
                   [&](auto&& r, auto&&) {
                     auto vo = vo::parse<vo::Route>(r.body());
                     assertFalse(vo.default_.has_value() &&
                                     egresses.find(*vo.default_) == end(egresses),
                                 PichiError::SEMANTIC_ERROR, "Unknown egress"sv);
                     assertTrue(all_of(cbegin(vo.rules_), cend(vo.rules_),
                                       [&](auto&& pair) {
                                         return egresses.find(pair.second) != end(egresses);
                                       }),
                                PichiError::SEMANTIC_ERROR, "Unknown egress"sv);
                     router.setRoute(move(vo));
                     return genResp(http::status::no_content);
                   }),
        make_tuple(http::verb::options, ROUTE_REGEX, [](auto&&, auto&&) {
                     return options({http::verb::get, http::verb::put, http::verb::options});
                   }),
        make_tuple(http::verb::post, CLEAR, [](auto&&, auto&&) {

                   }),
        }
{
}

Rest::Response Rest::handle(Request const& req)
{

  auto mr = cmatch{};
  auto it =
      find_if(cbegin(apis_), cend(apis_), [v = req.method(), t = req.target(), &mr](auto&& item) {
        return get<0>(item) == v && matching(t, get<1>(item), mr);
      });
  return it != cend(apis_) ? invoke(get<2>(*it), req, mr) : genResp(http::status::not_found);
}

Rest::Response Rest::errorResponse(exception_ptr eptr)
{
  try {
    rethrow_exception(eptr);
  }
  catch (Exception const& e) {
    return genResp(e2c(e.error()), vo::Error{e.what()});
  }
  catch (sys::system_error const& e) {
    return genResp(e2c(e.code()), vo::Error{e.what()});
  }
}

}  // namespace pichi::api
