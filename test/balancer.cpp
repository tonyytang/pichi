#define BOOST_TEST_MODULE pichi balancer test

#include "utils.hpp"
#include <array>
#include <boost/test/unit_test.hpp>
#include <cmath>
#include <pichi/api/balancer.hpp>
#include <pichi/common/literals.hpp>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

namespace pichi::unit_test {

using namespace api;

static auto const BALANCE_TYPES =
    array{BalanceType::RANDOM, BalanceType::ROUND_ROBIN, BalanceType::LEAST_CONN};

static auto const ENDPOINTS = invoke([]() {
  auto ret = array<Endpoint, 100_sz>{};
  for (auto i = 0_sz; i < ret.size(); ++i) {
    ret[i] = makeEndpoint("localhost", i);
  }
  return ret;
});

static auto const N = ENDPOINTS.size();

BOOST_AUTO_TEST_SUITE(BALANCER)

BOOST_AUTO_TEST_CASE(select_Empty)
{
  for (auto type : BALANCE_TYPES) {
    BOOST_CHECK_EXCEPTION((Balancer{type, cbegin(ENDPOINTS), cbegin(ENDPOINTS)}), Exception,
                          verifyException<PichiError::MISC>);
  }
}

BOOST_AUTO_TEST_CASE(select_Wrong_Order)
{
  for (auto type : BALANCE_TYPES) {
    BOOST_CHECK_THROW((Balancer{type, cend(ENDPOINTS), cbegin(ENDPOINTS)}), length_error);
  }
}

BOOST_AUTO_TEST_CASE(RANDOM_select_Probability)
{
  using Offset = typename iterator_traits<Balancer::Iterator>::difference_type;
  auto const K = 1000;
  auto data = unordered_map<Offset, int>{};
  auto balancer = Balancer{BalanceType::RANDOM, cbegin(ENDPOINTS), cend(ENDPOINTS)};
  for (auto i = 0_sz; i < N * K; ++i) ++data[distance(Balancer::Iterator{}, balancer.select())];

  BOOST_CHECK_EQUAL(N, data.size());
  for_each(cbegin(data), cend(data), [=, delta = sqrt(N * K) / 2.0](auto&& item) {
    BOOST_CHECK_LE(abs(item.second - K), delta);
  });
}

BOOST_AUTO_TEST_CASE(ROUND_ROBIN_select)
{
  auto balancer = Balancer{BalanceType::ROUND_ROBIN, cbegin(ENDPOINTS), cend(ENDPOINTS)};
  auto base = balancer.select();
  for_each(cbegin(ENDPOINTS) + 1, cend(ENDPOINTS),
           [it = base, &balancer](auto&&) mutable { BOOST_CHECK(balancer.select() == ++it); });
  for_each(cbegin(ENDPOINTS), cend(ENDPOINTS),
           [it = base, &balancer](auto&&) mutable { BOOST_CHECK(balancer.select() == it++); });
}

BOOST_AUTO_TEST_CASE(LEAST_CONN_select)
{
  using Offset = typename iterator_traits<Balancer::Iterator>::difference_type;
  auto container = unordered_set<Offset>{};
  auto balancer = Balancer{BalanceType::LEAST_CONN, cbegin(ENDPOINTS), cend(ENDPOINTS)};
  for (auto i = 0_sz; i < N; ++i) {
    generate_n(inserter(container, end(container)), N,
               [&balancer]() { return distance(Balancer::Iterator{}, balancer.select()); });
    BOOST_CHECK_EQUAL(N, container.size());
    container.clear();
  }
}

BOOST_AUTO_TEST_CASE(LEAST_CONN_release_No_Connection_Iterator)
{
  auto balancer = Balancer{BalanceType::LEAST_CONN, cbegin(ENDPOINTS), cend(ENDPOINTS)};
  auto it = balancer.select();
  balancer.release(it);
  for (auto i = 0_sz; i < N; ++i)
    BOOST_CHECK_EXCEPTION(balancer.release(it++), Exception, verifyException<PichiError::MISC>);
}

BOOST_AUTO_TEST_CASE(LEAST_CONN_release)
{
  auto balancer = Balancer{BalanceType::LEAST_CONN, cbegin(ENDPOINTS), cend(ENDPOINTS)};
  auto iterators = vector<Balancer::Iterator>{};
  generate_n(back_inserter(iterators), N, [&]() { return balancer.select(); });

  for_each(cbegin(iterators), cend(iterators), [&](auto it) {
    for (auto i = 0_sz; i < N; ++i) {
      balancer.release(it);
      BOOST_CHECK(it == balancer.select());
    }
  });
}

BOOST_AUTO_TEST_SUITE_END()

}  // namespace pichi::unit_test
