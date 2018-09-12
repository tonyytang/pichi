#include <pichi/asserts.hpp>

using namespace std;

namespace pichi {

[[noreturn]] void fail(PichiError e, string const& msg) {
  throw Exception{e, msg};
}

void assertTrue(bool b, PichiError e, string const& msg)
{
  if (!b) fail(e, msg);
}

void assertFalse(bool b, PichiError e, string const& msg) { assertTrue(!b, e, msg); }

} // namespace pichi