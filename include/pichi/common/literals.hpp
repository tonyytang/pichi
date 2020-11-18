#ifndef PICHI_COMMON_LITERALS_HPP
#define PICHI_COMMON_LITERALS_HPP

#include <cassert>
#include <limits>
#include <stddef.h>
#include <stdint.h>
#include <type_traits>

namespace pichi {

/* TODO
 * MSVC complains C4100 warnings if variant is not used in all branches of if-constexpr.
 * Suppress it explicitly by using following function tmeplate.
 */
template <typename... Args> void suppressC4100(Args&&...) {}

inline constexpr size_t operator""_sz(unsigned long long i)
{
  assert(i <= std::numeric_limits<size_t>::max());
  return static_cast<size_t>(i);
}

inline constexpr uint8_t operator""_u8(unsigned long long i)
{
  assert(i <= std::numeric_limits<uint8_t>::max());
  return static_cast<uint8_t>(i);
}

inline constexpr uint16_t operator""_u16(unsigned long long i)
{
  assert(i <= std::numeric_limits<uint16_t>::max());
  return static_cast<uint16_t>(i);
}

}  // namespace pichi

#endif  // PICHI_COMMON_LITERALS_HPP
