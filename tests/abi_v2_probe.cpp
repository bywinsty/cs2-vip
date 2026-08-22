#include "../include/vip.h"

#include <type_traits>

static_assert(std::is_base_of_v<IVIPApi001, IVIPApi002>);
static_assert(std::is_same_v<IVIPApi, IVIPApi002>);

void probe_v2(IVIPApi002* api)
{
    api->VIP_OpenMenu(0);
}
