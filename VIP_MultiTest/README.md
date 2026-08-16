# [VIP] MultiTest
My Discord server - https://discord.com/invite/g798xERK5Y

Allows regular players to take on VIP status
Before installing, customize the `vip_multitest.ini` file.

Commands:

```text
mm_vipmultitest
sm_vipmultitest
!vipmultitest
vipmultitest
```

Installed files:

```text
addons/
├── configs/vip/vip_multitest.ini
├── metamod/vip_multitest.vdf
└── vip_modules/vip_multitest.so
```

In **vip.phrases.txt** add:
```
	"VIPMultiTest_Title"
	{
		"en"	"Choose a VIP group"
		"ru"	"Выберите вип группу"
	}
```

## Обновление со старой версии

Начиная с этой версии `VIP_MultiTest` использует отдельный namespace `vip_multitest`:

| Назначение | Новый путь/ключ |
| --- | --- |
| Binary | `addons/vip_modules/vip_multitest.so` |
| Metamod VDF | `addons/metamod/vip_multitest.vdf` |
| Config | `addons/configs/vip/vip_multitest.ini` |
| Cookie | `vip_multitest` |
| Commands | `mm_vipmultitest`, `sm_vipmultitest`, `!vipmultitest`, `vipmultitest` |
| Translation key | `VIPMultiTest_Title` |

Старые файлы `vip_test.so`, `vip_test.vdf` и `vip_test.ini` не удаляйте автоматически.
Этот namespace теперь принадлежит модулю `VIP_Test`, поэтому перед ручной очисткой остановите
сервер и убедитесь, что файлы не используются `VIP_Test`. Read-only preflight-проверка:

```text
python3 .github/scripts/check_vip_multitest_upgrade.py /path/to/game
```

Код возврата `0` означает, что legacy-файлы не найдены, `2` — требуется ручная проверка,
`1` — неверный путь установки. Проверка ничего не удаляет и не изменяет.
