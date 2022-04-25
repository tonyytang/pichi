#ifndef PICHI_API_REST_HPP
#define PICHI_API_REST_HPP

#include <array>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/string_body.hpp>
#include <exception>
#include <functional>
#include <regex>
#include <tuple>

namespace pichi::api {

using boost::beast::http;

template <class TBody>
class RequestHandler {
public:
  virtual response<TBody>* handleRequest(request<TBody> const *) = 0;
};

template <class TBody>
class DelegateHandler : RequestHandler<TBody> {
public:
  RequestHandler<TBody>* inner;
  response<TBody>* handleRequest(request<TBody> const *) override;
};

template <class TBody>
class CorsDelegateHandler : DelegateHandler<TBody> {
public:
  response<TBody>* handleRequest(request<TBody> const *) override;
};

template <class TBody>
class Route : public std::tuple<verb, std::regex, RequestHandler<TBody>> {
public:
  response<TBody>* handleRequestIfMatches(request<TBody> const *);
};

template <class TBody>
class Config {
public:
  Config();
  ~Config();
  void addHandler(DelegateHandler<TBody> const *);
  void addRoute(Route<TBody> const &);
  response<TBody>* handleRequest(request<TBody> const *);
private:
  std::vector<Route<TBody>> _routes;
  DelegateHandler<TBody>* _handler;

  class RouteRequestHandler : DelegateHandler<TBody> {
  public:
    RouteRequestHandler(std::vector<Route<TBody>> * routes)
      : _routes(routes){}
    response<TBody>* handleRequest(request<TBody> const *) override;
  private:
    std::vector<Route<TBody>> * _routes;
  };
};

class EgressManager;
class IngressManager;
class Router;

class Rest {
public:
  using HttpBody = boost::beast::http::string_body;
  using Request = boost::beast::http::request<HttpBody>;
  using Response = boost::beast::http::response<HttpBody>;

  explicit Rest(IngressManager&, EgressManager&, Router&);
  Response handle(Request const&);

  static Response errorResponse(std::exception_ptr);

private:
  using HttpHandler = std::function<Response(Request const&, std::cmatch const&)>;
  using RouteItem = std::tuple<boost::beast::http::verb, std::regex, HttpHandler>;

  std::array<RouteItem, 18> apis_;
};

} // namespace pichi::api

#endif // PICHI_API_REST_HPP
