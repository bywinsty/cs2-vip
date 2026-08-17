#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "VIP_Fortnite_Hits"
HEADER = (MODULE / "source/include/fortnite_hits.h").read_text(encoding="utf-8")
SOURCE = (MODULE / "source/fh_vip.cpp").read_text(encoding="utf-8")


def main():
    required_header = (
        '#define FH_INTERFACE "IFortniteHitsApi"',
        '#define FH_INTERFACE_001 "IFortniteHitsApi001"',
        "class IFortniteHitsApi001",
        "virtual int GetApiVersion() = 0;",
        "virtual int GetAccessMode() = 0;",
    )
    required_source = (
        "MetaFactory(FH_INTERFACE_001",
        "GetApiVersion() != 1",
        "GetAccessMode() != FH_ACCESS_VIP",
        "VIP_OnClientLoaded(OnClientAuthorized)",
        "VIP_OnClientDisconnect(OnClientDisconnect)",
        "VIP_OnVIPClientAdded(OnVIPClientAdded)",
        "VIP_OnVIPClientRemoved(OnVIPClientRemoved)",
    )

    missing = [item for item in required_header if item not in HEADER]
    missing += [item for item in required_source if item not in SOURCE]
    if "MetaFactory(FH_INTERFACE, &ret" in SOURCE:
        missing.append("legacy Fortnite Hits API must not be used by the modern adapter")
    if missing:
        raise SystemExit("Fortnite Hits contract check failed:\n- " + "\n- ".join(missing))

    print("Fortnite Hits API contract check passed")


if __name__ == "__main__":
    main()
