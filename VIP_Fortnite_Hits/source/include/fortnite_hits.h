#pragma once

#define FH_INTERFACE "IFortniteHitsApi"
#define FH_INTERFACE_001 "IFortniteHitsApi001"

enum FortniteHitsAccessMode
{
	FH_ACCESS_FREE = 0,
	FH_ACCESS_VIP = 1,
};
class IFortniteHitsApi
{
public:
	virtual void GiveClientAccess(int iSlot) = 0;
	virtual void TakeClientAccess(int iSlot) = 0;
};

class IFortniteHitsApi001
{
public:
	virtual int GetApiVersion() = 0;
	virtual int GetAccessMode() = 0;
	virtual void GiveClientAccess(int iSlot) = 0;
	virtual void TakeClientAccess(int iSlot) = 0;
};
