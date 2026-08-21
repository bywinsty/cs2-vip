# [VIP] CORE | LIST OF MODULES - [click](https://github.com/Pisex/cs2-vip-modules)

## Requirements
- CS2 server on Linux x86-64 (Windows builds are not currently published or supported)
- [sql_mm](https://github.com/zer0k-z/sql_mm) plugins; sql_mm is an external dependency and is not included in the VIP release archive
- Database data configured in `addons/configs/databases.cfg`

For crash diagnostics, install [Accelerator](https://github.com/komashchenko/AcceleratorLocal/releases/tag/v1.0.0) and send the generated crash file.

## Release archive
The archive contains:
```text
addons/
├── metamod/vip.vdf
├── vip/vip.so
├── configs/databases.cfg
├── configs/vip/groups.ini
├── translations/vip.phrases.txt
└── data/vip_data.ini
```

## Commands
Client command:

- `!vip` - plugin main menu

Console commands:
- `vip_reload` - reload VIP configuration with groups
- `vip_remove <userid|nickname|accountid>` - remove VIP access from a player
- `vip_give <userid|nickname|accountid> <time_second> <group>` - give VIP access to a player

## Configuration
- Database file: `addons/configs/databases.cfg`
- Groups file: `addons/configs/vip/groups.ini`
- Translation file: `addons/translations/vip.phrases.txt`

## Account ID migration

VIP persistence uses SteamID64. Existing SQL rows with the legacy 32-bit
account key are read as a fallback and migrated on client authorization. The
local KeyValues cookie backend performs the same migration, and numeric IDs
passed to `vip_give` are normalized to SteamID64 before insertion.
