[EN](README.md) | [UA](README-UA.md)

# [VIP] [Fortnite Hits](https://github.com/bywinsty/cs2-vip-modules/tree/main/VIP_Fortnite_Hits)

## Связывает VIP-доступ с плагином Fortnite Hits. Этот модуль сам не отображает урон, а вызывает внешний `IFortniteHitsApi001` для выдачи или отзыва доступа VIP-игрокам.

Перед этим модулем установите и загрузите плагин Fortnite Hits. Настройте его с `access_mode "vip"`; standalone/free-режим предназначен для работы без этого модуля.

### Ключ возможности

В `groups.ini` добавьте:

```
"fortnite_hits" "1/0"
```

### Ключ перевода

В `vip.phrases.txt` добавьте ключ `fortnite_hits`.

```
"fortnite_hits"
{
    "en" "Damage Display"
    "ru" "Отображение урона"
}
```
