# RBAC и защита инфраструктурных секретов

Документ относится к ветке `feature/remnawave-2.8.1-rbac`, Remnawave Admin 3.1.1 и контракту Remnawave 2.8.1.

## Модель разрешений

Разрешение хранится как пара `resource:action`. Новая системная роль `infrastructure_admin` создаётся миграцией `0091`.

| Ресурс | Действия |
|---|---|
| `nodes` | `view`, `create`, `edit`, `delete`, `restart`, `enable`, `disable`, `secrets_view`, `secrets_edit` |
| `hosts` | `view`, `create`, `edit`, `delete` |
| `config_profiles` | `view`, `create`, `edit`, `delete`, `secrets_view`, `secrets_edit`, `full_edit` |
| `subscription_templates` | `view`, `create`, `edit`, `delete` |
| `snippets` | `view`, `create`, `edit`, `delete` |
| `node_agents` | `view`, `manage`, `tokens_manage`, `install` |

`infrastructure_admin` по умолчанию получает:

- ноды: просмотр, создание, редактирование, restart/enable/disable;
- хосты: просмотр, создание, редактирование;
- профили: просмотр, создание и безопасное редактирование.

Роль не получает delete, `secrets_*`, `full_edit`, Node Agent, пользователей, подписки, администраторов, роли, финансы, API keys, системные настройки, логи, backups, templates/snippets и squads.

Миграция переносит старые `resources:{view,create,edit,delete}` в отдельные безопасные CRUD-разрешения профилей, subscription templates и snippets. Секретные права из старого `resources` не выводятся. Старое `nodes:edit` сохраняет прежние lifecycle-действия, но не даёт доступ к Node Agent.

## Access Policies

Политика может ограничивать `node`, `host`, `squad`, `user` и `config_profile`:

- `uuid` — один объект;
- `tag` — ноды или хосты с тегом;
- `all` со значением `*` — все объекты типа.

Для нод отдельно ограничиваются `view`, `edit`, `delete`, `restart`, `enable`, `disable`. Scope применяется к спискам, объектам, lifecycle и bulk-операциям. Объект вне scope возвращается как отсутствующий. Создание запрещено при UUID/tag whitelist, потому что новый UUID не может безопасно сам попасть в whitelist. Редактирование общего профиля запрещается, если профиль назначен хотя бы одной ноде вне edit-scope администратора.

Администратор инфраструктуры не имеет прав управления ролями и Access Policies, поэтому не может расширить собственный scope.

## Secret-safe API профилей

Без `config_profiles:secrets_view` ответы рекурсивно маскируют `privateKey`, `secretKey`, PSK, пароли/auth/token в credential-контейнерах и client `id/uuid` значением `********`. Это применяется к profile, inbounds, computed config, истории версий и внутреннему proxy.

Сохранение выполняется только так:

1. backend заново читает полный профиль из Remnawave;
2. сравнивает `If-Match` с SHA-256 revision полного доверенного документа;
3. сопоставляет защищённые элементы массивов по стабильной identity, а не по позиции;
4. восстанавливает маски из свежего оригинала;
5. отклоняет удаление, `null`, замену, дубликат, переименование tag и перестановку защищённых объектов;
6. отправляет в Remnawave полный merged JSON.

Без `full_edit` разрешены изменения `inbounds` и безопасных полей `log`; routing, DNS, outbounds и прочие произвольные секции закрыты. Изменение секретных значений требует `secrets_edit`. Структурное произвольное редактирование требует `full_edit`. Нетипизированный internal proxy не принимает изменения профилей от обычных RBAC-администраторов.

## Node SecretKey и Node Agent

Node/API secret-поля рекурсивно маскируются без `nodes:secrets_view`. Схемы обычного update не принимают неизвестные secret-поля, поэтому ограниченный администратор не может затереть `SecretKey` подменённым JSON.

`WEB_SECRET_KEY` используется для JWT и никогда не помещается в install-команду. Для новых агентов задаётся отдельный:

```env
NODE_AGENT_HMAC_SECRET=<openssl-rand-hex-32>
```

Новые agent tokens имеют префикс `v2.`. Install-команда получает HMAC-производную от отдельного корня и токена конкретной ноды. Backend сохраняет legacy-подпись для старых токенов без префикса, поэтому миграция по нодам не требует одновременного простоя.

Без `NODE_AGENT_HMAC_SECRET` уже установленные legacy-агенты работают, но создание install-команд возвращает 503. После добавления секрета открытие install-команды для legacy-ноды ротирует только её token в `v2.`; новую команду нужно сразу выполнить на этой ноде.

Рекомендуемый порядок:

1. развернуть код, не меняя `WEB_SECRET_KEY`;
2. добавить отдельный `NODE_AGENT_HMAC_SECRET` и перезапустить backend;
3. по одной ноде получить и выполнить новую install-команду;
4. убедиться, что все активные agent tokens начинаются с `v2.`;
5. только после этого при необходимости ротировать `WEB_SECRET_KEY` (это завершит все web-сессии и отключит забытые legacy-агенты).

## Аудит и логи

Разрешённые изменения, lifecycle, token rotation и отказы RBAC записываются в audit. Central audit sanitizer заменяет password/token/secret/private key/API key на `[REDACTED]`. Ошибки Panel API для profile JSON не возвращают и не логируют исходное тело, которое могло содержать ключ.

## Обновление Docker Compose

Compose собирает `bot`, `web-backend`/`web-collector` и `web-frontend` из текущего checkout. Named volumes `postgres_data`, `geoip_data`, `redis_data`, `prometheus_data` сохраняются. Не используйте `docker compose down -v`.

Обычное обновление текущего клона:

```bash
cd /opt/remnawave-admin
git fetch origin
git switch feature/remnawave-2.8.1-rbac
git pull --ff-only origin feature/remnawave-2.8.1-rbac
cp .env .env.pre-rbac
grep -q '^NODE_AGENT_HMAC_SECRET=' .env || \
  printf '\nNODE_AGENT_HMAC_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env
docker compose build --pull bot web-backend web-frontend
docker compose up -d --remove-orphans
docker compose exec web-backend alembic upgrade head
docker compose ps
docker compose logs --tail=100 web-backend web-frontend
```

Если старый сервер использовал только опубликованные GHCR images, сначала сохраните `.env` и данные, затем клонируйте ветку в отдельный каталог и подключите тот же compose project name, чтобы Docker использовал существующие named volumes:

```bash
cd /opt
git clone --branch feature/remnawave-2.8.1-rbac \
  https://github.com/Case211/remnawave-admin.git remnawave-admin-rbac
cd remnawave-admin-rbac
cp /opt/remnawave-admin/.env .env
printf '\nNODE_AGENT_HMAC_SECRET=%s\n' "$(openssl rand -hex 32)" >> .env
docker compose -p remnawave-admin build --pull bot web-backend web-frontend
docker compose -p remnawave-admin up -d --remove-orphans
docker compose -p remnawave-admin exec web-backend alembic upgrade head
```

Перед вторым сценарием проверьте фактическое имя старого проекта через `docker compose ls`; значение `-p` должно совпасть, иначе будут созданы новые пустые volumes.

Rollback приложения выполняется возвратом предыдущего commit/image и обычным `up -d`, без удаления volumes. Downgrade БД используйте только если старый код действительно несовместим с добавочными permissions/constraints:

```bash
docker compose exec web-backend alembic downgrade 0090
```

Перед rollback сохраните дамп PostgreSQL. Миграция `0091` не меняет конфиги Remnawave и не удаляет инфраструктурные объекты.
