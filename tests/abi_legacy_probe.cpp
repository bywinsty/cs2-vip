#include "../include/vip.h"

void probe_legacy(IVIPApi001* api)
{
    (void)api->VIP_IsVIPLoaded();
    api->VIP_RegisterFeature("probe");
}
