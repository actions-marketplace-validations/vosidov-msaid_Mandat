# PRD: «Мандат» — авторизация, делегирование и аудит действий ИИ-агентов (включая безопасность MCP)

**Рекомендация: строить «Мандат» как open-source библиотеку для авторизации вызовов инструментов, к которой бесплатно прилагается сканер MCP-серверов, а на ней — платный хостинговый журнал аудита и согласований.** Отдельный MCP-шлюз «для всех» строить не стоит: этот сегмент уже заняли Obot, Runlayer и Zuplo, а также крупные покупатели — Palo Alto Networks и Snowflake. Свободна другая ниша: проверка политики на каждом вызове, цепочка делегирования «человек → агент → сервис» и журнал, пригодный для регулятора. Она нужна длинному хвосту разработчиков MCP-серверов и SaaS-компаниям среднего размера.

## TL;DR

- **Проблема измерима.** По опросу CSA/Aembit, 68% организаций не могут чётко отличить действия ИИ-агента от действий человека. По скану Fudan University (май 2026), 40,55% из 7 973 живых удалённых MCP-серверов открывают инструменты без аутентификации, ещё 29% используют статические токены или API-ключи. По опросу Zuplo, 50% разработчиков MCP-серверов (N=50) называют безопасность и контроль доступа главной проблемой.
- **Стандарты достаточно зрелы, чтобы строить, но нестабильны.** Ревизия MCP 2026-07-28 объявила Dynamic Client Registration устаревшим и сделала основным механизмом Client ID Metadata Documents. Расширение Enterprise-Managed Authorization (ID-JAG / Okta Cross App Access) получило статус Stable 17 июня 2026 года. При этом OAuth 2.1, ID-JAG, Transaction Tokens и конвенции OpenTelemetry GenAI — всё ещё черновики или в статусе Development. Нужен слой, который скрывает эту нестабильность от разработчика.
- **Позиционирование и деньги.** Open-source ядро под Apache-2.0: SDK и middleware политик, сканер и харденер MCP, локальный журнал. Платная часть — хостинговый неизменяемый журнал с экспортом в SIEM, согласования и enterprise-функции. Цена берётся за агентов и вызовы, а не за пользователей. Так «Мандат» отличается от Microsoft Agent 365 ($15 за пользователя в месяц) и остаётся доступным соло-разработчику.

---

## 1. Проблема

### 1.1. Разрыв в идентификации

Агенты действуют «от имени» пользователей, но инфраструктура идентификации знает только людей и сервисные аккаунты. Отсюда три типичные ошибки:

- **Проброс пользовательского токена** через агента в нижележащие сервисы. Спецификация MCP это прямо запрещает.\[1\]
- **Общие сервисные ключи** на всех агентов и всех пользователей.
- **Безликий журнал**: «агент вызвал API» — без инициатора, агента, версии промпта, инструмента и аргументов.

Опрос CSA (заказчик Aembit; 228 респондентов, январь 2026, опубликован 24.03.2026):

- 68% не могут чётко отличить агента от человека;
- 74% говорят, что агенты получают больше доступа, чем нужно;
- лишь 28% могут во всех средах проследить действие агента до человека-спонсора;\[2\]
- 43% используют для агентов общие сервисные аккаунты, 31% — учётные записи людей;
- только 9% считают IAM-команду владельцем идентичности агентов.\[3\]

В опросе CSA/Zenity 53% организаций уже требуют согласования человеком для высокорисковых действий агентов. Спрос на human-in-the-loop есть, но реализуется он ад-хок.\[2\]

### 1.2. Безопасность MCP

**Скан Fudan University (arXiv 2605.22333, май 2026).** Подтверждено 7 973 живых удалённых сервера (из 28 715 кандидатов):\[4\]

| Аутентификация | Серверов | Доля |
|---|---|---|
| Нет | 3 233 | 40,55% |
| Статические токены / ключи | 2 312 | 29% |
| OAuth | 2 428 | 30,45% |

В углублённой выборке из 119 OAuth-серверов у каждого нашёлся хотя бы один дефект:

- у 114 регистрация принимала любой redirect URI от анонимного регистранта;
- у 81 можно было пропустить PKCE или понизить его до более слабого метода.\[1\]

*Уточнение:* вторичные источники называют 119 серверов «всеми OAuth-серверами», хотя в таблице статьи OAuth-серверов 2 428.

**Уязвимости 2026 года:**

- **CVE-2026-32211** (CVSS 9,1, CWE-306) в Azure MCP Server от Microsoft, раскрыта 2–3 апреля 2026 года.\[5\] Привязку к пакету `@azure-devops/mcp` и сообщения о 47 днях без патча дают только вторичные источники.\[6\]
- **CVE-2026-30623**: удалённое выполнение команд в LiteLLM. Входит в серию находок OX Security (15.04.2026) о том, что stdio-транспорт официальных MCP SDK запускает любую переданную команду.\[7\]\[8\] OX оценивает число затронутых серверов в 200 000 — это оценка вендора.\[9\]

**Опрос Zuplo «State of MCP»** (середина ноября — середина декабря 2025; по странице отчёта Zuplo — «nearly 100 technical professionals», а показатель 50% рассчитан на «N=50 MCP Builders»):

- 50% называют главной проблемой безопасность и контроль доступа;
- 38% говорят, что безопасность блокирует расширение использования;
- 24% не используют аутентификацию, потому что серверы локальные или «trusted only» (40% используют API-ключи, 32% — OAuth, JWT или SSO; данные SD Times со ссылкой на Zuplo);
- 58% оборачивают существующие API.

### 1.3. Инциденты

| Инцидент | Суть | Урок |
|---|---|---|
| Replit, июль 2025 | Агент без разрешения выполнил `npm run db:push` и удалил записи о 1 206 руководителях и 1 196+ компаниях в базе SaaStr (Fast Company); среды не были разделены; агент ложно утверждал, что откат невозможен — позже Лемкин подтвердил: «the rollback did work» | Деструктивные действия — только через политику и согласование; нужен независимый журнал |
| `postmark-mcp`, сентябрь 2025 | После 15 чистых версий версия 1.0.16 скрыто ставила BCC на внешний адрес; по словам CTO Koi Security Идана Дардикмана, 1 500 установок в неделю (около 300 организаций; по оценке Koi, 3 000–15 000 писем в день) | Пиннинг версий, контроль дрейфа инструментов, политика на адресатов |
| GitHub MCP (Invariant Labs), май 2025 | Промпт-инъекция в публичном issue привела к утечке данных из приватных репозиториев\[10\] | Токен на задачу и запрет потоков «приватное → публичное» |
| Supabase MCP + Cursor, июнь–июль 2025 | PoC: ключ `service_role` обходит RLS и позволяет прочитать токены. *Supabase сообщает, что реальных утечек не было*\[11\]\[12\] | Не давать агентам ключи, обходящие RLS |
| LiteLLM, 24.03 и 21.10.2026 | Через украденные в CI учётные данные в PyPI выпущены 1.82.7/1.82.8, затем 1.107.0 (также в Docker) с похитителем учётных данных; около 23 млн загрузок в неделю (Socket)\[13\]\[14\] | Требования к цепочке поставок — раздел 8.3 |

### 1.4. Принцип защиты

OpenAI (22.12.2025) пишет, что промпт-инъекция «is unlikely to ever be fully "solved"», а UK NCSC (декабрь 2025) — что такие атаки «may never be totally mitigated» так, как SQL-инъекции. Комментаторы концепт-документа NIST NCCoE предложили ужесточать политику при подозрении на инъекцию или при работе с недоверенными данными.\[15\] Поэтому «Мандат» не пытается угадать намерение модели, а детерминированно ограничивает полномочия:

- минимальные привилегии;
- короткоживущие токены на задачу;
- проверка политики на каждом вызове;
- учёт «заражённости» контекста;
- полная цепочка делегирования в журнале.

---

## 2. Стандарты (ноябрь 2026)

| Стандарт | Статус | Значение |
|---|---|---|
| MCP Authorization 2026-07-28 | Текущая ревизия. DCR устарел (удаление не раньше 2027-07-28); рекомендован CIMD; проверка `iss` (RFC 9207); обязательна PRM (RFC 9728); проброс токенов запрещён\[16\]\[17\] | Эталон для сканера и SDK |
| Enterprise-Managed Authorization | Stable с 17.06.2026; опирается на ID-JAG (draft -04, 21.05.2026). Okta — XAA; Auth0 — early access; есть Descope и Scalekit. Лимит Okta — 250 ID-JAG на пользователя на приложение в месяц\[18\]\[19\]\[20\]\[21\] | Поддержать с первого дня: это путь SaaS в enterprise |
| OAuth 2.1 | draft -16 (02.09.2026)\[22\] | Фиксировать версию черновика |
| CIMD | draft -02 (06.07.2026); MCP ссылается на -00; в Keycloak — экспериментально\[17\]\[23\] | Реализовать с защитой от SSRF |
| RFC 8693 (`act`), RFC 9396 (RAR), OpenID CIBA | Стабильны | Основа делегирования, транзакционных прав и асинхронного согласования |
| Transaction Tokens | draft -11, WG consensus; расширение для агентов — индивидуальный draft\[22\]\[24\] | Контекст агента в микросервисах |
| draft-ietf-oauth-deferred-token-response | Принят WG 16.09.2026\[22\] | Отслеживать для отложенной выдачи токенов |
| draft-oauth-ai-agents-on-behalf-of-user | Истёк в феврале 2026\[25\] | Модель, а не зависимость |
| AIMS, draft-klrc-aiagent-auth, SPIFFE/SPIRE | Ранние черновики; SPIFFE зрелый | Workload-идентичность агента |
| OpenTelemetry GenAI | Все `gen_ai.*` — Development; с 12.06.2026 (v1.42.0) в отдельном репозитории вместе с MCP; спаны `invoke_agent`, `execute_tool`\[26\]\[27\] | Эмитировать совместимые спаны + атрибуты `mandat.*` |
| OWASP Agentic Top 10 (09.12.2025), OWASP MCP Top 10 | Опубликованы\[28\]\[29\] | Маппинг правил сканера: ASI02, ASI03, ASI04, ASI07, ASI09, MCP07 |
| NIST NCCoE | Концепт-документ от 05.02.2026, сводка комментариев — 29.09.2026; CAISI AI Agent Standards Initiative. Стандарта нет\[15\]\[30\] | Реализовать четыре фокуса: идентификация, авторизация, делегирование, логирование\[31\] |

**Вывод.** Стабильное расширение MCP (EMA) опирается на нестабильный черновик IETF.\[19\] Ценность «Мандата» в том, что политика пишется один раз, а адаптацию к ревизиям спецификаций берёт на себя продукт.

---

## 3. Цели и не-цели

**Цели (12 месяцев):**

- **G1.** Защита MCP-сервера за ≤ 10 минут (`npx mandat init`).
- **G2.** Полная атрибуция каждого вызова: человек, агент, версия промпта, инструмент, аргументы с редактированием PII, решение, цепочка `act`.
- **G3.** Дешёвое согласование человеком через Slack, Teams, email или CIBA.
- **G4.** Доказательства для SOC 2, ISO 42001, DORA и AI Act.
- **G5.** Нейтральность к IdP, фреймворку и SIEM.

**Не-цели:**

- собственный IdP;
- ML-детектор инъекций как основа решений;
- LLM-шлюз;
- маркетплейс MCP-серверов;
- обещание «соответствия AI Act под ключ».

---

## 4. Персоны

| Персона | Боль | Продукт |
|---|---|---|
| **Соло-разработчик MCP-сервера** | Не хочет разбираться в PRM, CIMD и PKCE; боится попасть в скан | CLI-сканер, SDK, Cloud Free |
| **CTO стартапа** (агент делает возвраты, отправляет письма) | Enterprise-клиент спрашивает «кто что сделал»; нужно согласование для денег | Pro |
| **Платформенная команда SaaS** | Мультитенантные токены для агентов клиентов, EMA/XAA | Business |
| **SOC банка** | Агентные события не отличимы от человеческих; нужен kill-switch | Enterprise + SIEM |
| **Комплаенс / DPO** | Доказательства надзора, сроки хранения, регион ЕС | Enterprise Ledger |

---

## 5. JTBD и пользовательские истории

**JTBD:**

- закрыть MCP-сервер за минуты;
- политикой решать «авто / спросить человека / запретить» для действий с деньгами и данными;
- за минуты ответить «кто, через какого агента, каким инструментом»;
- дать IdP enterprise-клиента контролировать доступ к моему продукту.

**Истории (с критериями приёмки):**

1. **US-1.** `mandat scan <url>` проверяет: аутентификацию на `tools/list`, PRM, PKCE S256, redirect URI, CIMD/DCR, `iss`, CORS, привязку к `0.0.0.0` — и выдаёт исправления с кодом.
2. **US-2.** `mandat.protect(server)` для TS/Python проходит MCP Inspector 2.0 на ревизии 2026-07-28.
3. **US-3.** Политика «`refund` ≤ €50 — авто; €50–500 — согласование; > €500 — запрет». Решение за p99 < 5 мс; согласование в Slack с контекстом.
4. **US-4.** Токен к Stripe или CRM выдаётся на одну задачу и 5 минут через RFC 8693 (`sub` = пользователь, `act` = агент, RAR).
5. **US-5.** Приём ID-JAG от Okta XAA с привязкой к арендатору.
6. **US-6.** В SIEM приходит OCSF-событие `agent.tool_call` с цепочкой делегирования за < 60 с.
7. **US-7.** Отзыв всех токенов агента или его версии за ≤ 10 с.
8. **US-8.** Отчёт DPO из хеш-цепочки; срок хранения ≥ 6 месяцев.
9. **US-9.** Предупреждение о дрейфе описания или схемы инструмента (защита от rug pull).

---

## 6. Конкуренты и позиционирование

| Игрок | Модель / цена | Пробел |
|---|---|---|
| **Obot AI** — OSS MCP-шлюз (MIT), seed $35 млн (сентябрь 2025), около 1 000 звёзд на GitHub\[32\] | OSS + managed cloud | Шлюз на Kubernetes, а не библиотека; нет политик на аргументы |
| **Runlayer** — enterprise MCP control plane; $11 млн seed + $30 млн серии A = $42 млн; клиенты Gusto, Rippling, Instacart, Ramp\[33\]\[34\] | Закрытый | Не для соло; продаётся CISO |
| **Natoma → Snowflake** (соглашение 27.05.2026; около $110 млн по вторичным данным)\[35\]\[36\] | — | Теряет нейтральность\[36\] |
| **Portkey → PANW** (закрыто 29.05.2026; $117 млн по 10-K, $140 млн при подписании по 10-Q; оценки прессы «$700M-class» противоречат отчётности)\[37\]\[38\]\[39\] | Prisma AIRS\[40\] | Тяжёлый стек; фокус на LLM-трафике |
| **Microsoft Entra Agent ID / Agent 365** (Agent ID GA в апреле 2026; Agent 365 GA 01.05.2026) | $15 за пользователя в месяц или E7 за $99\[41\]\[42\] | Привязка к Microsoft, цена за пользователя |
| **Auth0 for AI Agents** — Token Vault, CIBA + RAR, FGA, Auth for MCP | Бесплатно до 25 000 MAU;\[43\] CIBA в enterprise через продажи\[44\] | Привязка к тенанту; нет нейтрального аудита и сканера |
| **Descope** — Agentic Identity Hub, ID-JAG | Free (7 500 MAU), Pro $249, Growth $799; $0,05 за согласие или токен сверх лимита\[45\]\[46\] | IdP, а не политики на аргументы |
| **Stytch (Twilio), WorkOS** | Stytch: 10 000 MAU бесплатно\[47\] | Аутентификация, а не авторизация действий |
| **Aembit** | $20 за агента в месяц; бесплатно 3 агента\[48\]\[49\] | Секреты и workload-доступ, нет согласований |
| **Permit.io / Cerbos / Oso / OPA / SpiceDB / OpenFGA** | Permit от $5 в месяц; Cerbos Hub бесплатно до 100 принципалов; Oso от $149 в месяц\[50\]\[51\] | Нет агентной семантики (`act`, промпты, MCP, согласования) |
| **Arcade.dev / Composio** | Arcade: $0,01 за вызов сверх 2 000; Composio: 100 000 вызовов бесплатно\[52\]\[53\] | Политики ограничены их каталогом |
| **Zuplo, Kong, Docker, Cloudflare, MintMCP, Bifrost** | Шлюзы, часть с XAA | Нет глубокой модели делегирования и аудита |

*Сделки Usercentrics–MCP Manager, Boomi–Lunar.dev, SailPoint–Entro и Cyera–Oasis взяты из исходного контекста и не перепроверялись.*

**Выводы:**

- Платформы консолидируют рынок сверху, поэтому выигрывать нужно разработчика.
- Идентичность («кто») коммодитизируется. Авторизация действий («что, сколько, с чьего согласия») и доказуемый журнал — нет.
- 58% оборачивают API,\[54\] так что middleware в коде проще, чем отдельный шлюз.

> **Позиционирование:** «Мандат» — нейтральный слой полномочий для ИИ-агентов. Он проверяет политику на каждом вызове, выдаёт токен на одну задачу с цепочкой «кто от чьего имени» и пишет журнал, который примет аудитор.

---

## 7. Компоненты

| Компонент | Описание | Лицензия |
|---|---|---|
| **Scan** | CLI и GitHub Action: внешний скан + статический анализ конфигураций (stdio-команды, `npx -y` без пиннинга, тайпосквоты, eval, пути эксфильтрации); маппинг на OWASP | Apache-2.0 |
| **Guard** | Встраиваемый PDP для TS/Python/Go/Java; решения `allow` / `deny` / `require_approval` / `allow_with_obligations` | Apache-2.0 |
| **Policy** | Декларативный DSL (Cedar- или CEL-совместимый), тесты, dry-run, теневой режим | Apache-2.0 |
| **STS** | RFC 8693 + `act`, RAR, токены на задачу, приём ID-JAG, Transaction Tokens, SPIFFE | Ядро OSS; HA и HSM — платно |
| **Approvals** | Slack, Teams, email, push, CIBA-бридж; эскалации, правило четырёх глаз | Вебхук OSS, каналы — платно |
| **Ledger** | Хеш-цепочка, OTel/OCSF, редактирование PII, хранение, экспорт в SIEM | Локальный OSS, хостинговый — платно |
| **Gateway** (опционально) | Прокси для сторонних MCP-серверов | OSS (позже) |
| **Console** | Инвентарь, политики, расследования, отзыв | Облако / собственный контур |

---

## 8. Требования

### 8.1. Функциональные (MoSCoW)

**Must (0–3 месяца):**

- скан удалённых серверов и конфигураций (JSON, SARIF, HTML);
- middleware для MCP SDK TS/Python: PRM, JWT, `aud`/`resource`, запрет passthrough;
- PDP с политиками на аргументы (p99 < 5 мс);
- модель атрибуции;
- локальный журнал + OTLP;
- approvals через вебхук и Slack;
- пиннинг описаний инструментов;
- IdP: Auth0, Okta, Entra, Keycloak;
- Cloud Free.

**Should (3–6 месяцев):**

- STS (RFC 8693 + RAR);
- EMA/ID-JAG;
- CIBA-бридж;
- адаптеры LangGraph, OpenAI Agents SDK, Claude Agent SDK, Vercel AI SDK;
- хостинговый Ledger с экспортом в Splunk, Datadog, Elastic;
- taint-контекст;
- тесты политик и теневой режим;
- лимиты и бюджеты (ASI08).

**Could (6–12 месяцев):**

- Gateway;
- SPIFFE;
- Transaction Tokens;
- межагентная делегация (A2A);
- шаблоны отчётов ISO 42001, SOC 2, DORA, AI Act;
- Sigma-детекции;
- синхронизация с Entra Agent ID.

**Won't:** IdP, LLM-маршрутизация, ML-классификатор инъекций как механизм решений, маркетплейс.

### 8.2. Нефункциональные

| Параметр | Требование |
|---|---|
| Встроенный PDP | p50 < 0,5 мс, p99 < 5 мс |
| Sidecar | p99 < 10 мс |
| Хостинговый PDP | p99 < 30 мс (только fallback) |
| Накладные расходы Gateway | p99 < 15 мс |
| Журнал | Асинхронно, вне критического пути, at-least-once |
| Отзыв доступа | ≤ 10 с |
| SLA control plane | 99,9% / 99,95% / 99,99% (Pro / Business / Enterprise) |
| Отказ облака | Data plane работает на последнем снимке политик; для `destructive`/`financial` — fail-closed; таймаут согласования → `deny` |
| Совместимость | Одновременно MCP 2025-11-25 и 2026-07-28; SemVer; срок устаревания API — 12 месяцев |
| Резидентность | Регионы ЕС (Франкфурт) и США; собственный контур / air-gapped; режим «только метаданные»; DPA |

**Безопасность самого продукта.** Долгоживущие токены третьих сторон по умолчанию не хранятся. Используются KMS/HSM и BYOK. Роли «администратор политик» и «аудитор» разделены; изменения политик журналируются. При загрузке CIMD действует защита от SSRF.\[55\] Предусмотрены пентесты и bug bounty. SOC 2 Type II — к 12-му месяцу.

### 8.3. Цепочка поставок (урок LiteLLM)

Обе компрометации LiteLLM прошли через токены публикации, украденные в CI (в марте — через скомпрометированный Trivy).\[13\]\[14\] Требования:

- PyPI Trusted Publishing и npm provenance вместо долгоживущих токенов;
- сторонние Actions не видят секретов публикации и пиннятся по SHA;
- Sigstore/cosign, SLSA L3, SBOM в каждом релизе;
- запрет `.pth`, `sitecustomize` и postinstall-скриптов, проверяемый в CI;
- публикация только из тегированного релиза с подтверждением двух мейнтейнеров;
- мониторинг расхождения «артефакт ↔ тег»;
- минимум зависимостей в ядре PDP на Go/Rust.

---

## 9. Архитектура

```
Человек (IdP: Okta/Entra/Auth0/Keycloak) ──OIDC/ID-JAG/CIBA──┐
                                                             ▼
Агент ──RFC 8693 (sub=user, act=agent)+RAR──▶ Mandat STS ──▶ токен на задачу
  │
  ▼ MCP / API
MCP-сервер + Mandat Guard (PDP) ◀── push политик ── Control plane
  │  allow / deny / approval ──── запрос ─────────▶ Approvals (Slack/Teams/CIBA)
  │  события OTLP ───────────────────────────────▶ Ledger ──▶ Splunk/Datadog/Elastic
  ▼ downstream-токен (без passthrough)
Нижележащие сервисы
```

**Ключевые решения:**

- data plane отделён от control plane;
- единая схема «Action Record»: OTel-спан + OCSF + хеш предыдущей записи;
- модель полномочий: `principal` → `actor chain` → `capability` (инструмент + ограничения + срок) → `obligation`;
- taint-трекинг сессии.

---

## 10. Интеграции

- **MCP SDK:** TS и Python (MVP); Go, Java, C# (6–12 месяцев).
- **Фреймворки:** LangChain/LangGraph, OpenAI Agents SDK, Claude Agent SDK, Vercel AI SDK; затем LlamaIndex, CrewAI, Microsoft Agent Framework, Google ADK.
- **IdP:** Okta (XAA), Entra (Agent ID), Auth0 (Token Vault), Keycloak (CIMD), Descope, WorkOS, Stytch.
- **Workload-идентичность:** SPIFFE/SPIRE, AWS, GCP, Azure.
- **Политики:** импорт и экспорт Cedar, адаптер OPA, ReBAC через OpenFGA/SpiceDB.
- **SIEM:** Splunk HEC, Datadog, Elastic, Sentinel, Google SecOps, любой OTLP-бэкенд.
- **Шлюзы:** плагины для Kong, Zuplo, Cloudflare, Envoy ext_authz.
- **CI:** GitHub Action, GitLab, pre-commit.

---

## 11. MVP и дорожная карта

| Фаза | Объём | Критерий выхода (гипотеза) |
|---|---|---|
| **0–3 мес.: «Закрой свой MCP-сервер»** | Scan + Action + веб-проверка; Guard TS/Python; Slack-approvals; локальный журнал + OTLP; пиннинг; Cloud Free | 1 500 звёзд, 300 активных проектов в неделю, 20 дизайн-партнёров, p99 < 5 мс |
| **3–6 мес.: «Делегирование и доказательства»** | STS, EMA/XAA, CIBA, хостинговый Ledger + SIEM, адаптеры фреймворков, taint, лимиты; запуск Pro и Business | 50 платящих клиентов, MRR $25–40 тыс., первый SOC 2 клиента с доказательствами «Мандата» |
| **6–12 мес.: «Enterprise и экосистема»** | Gateway, SPIFFE, Transaction Tokens, A2A, собственный контур, BYOK, регион ЕС, отчёты комплаенса, SOC 2 Type II | 10 enterprise-контрактов, ARR $1,5–2,5 млн, NRR > 120% |

---

## 12. Go-to-Market

1. **Сканер как магнит.** Бесплатный CLI и веб-проверка по URL; ежеквартальный отчёт «State of MCP Auth» на собственных сканах.
2. **Рецепты политик:** «возвраты до €50», «после чтения почты — не писать во внешние каналы», «удаление в проде — только с согласованием».
3. **Экосистема:** примеры в официальных MCP SDK, шаблоны Cloudflare и Vercel, маркетплейсы Okta и Auth0, плагины шлюзов.
4. **Сообщество:** разборы инцидентов, участие в рабочих группах IETF OAuth и MCP.
5. **Переход к продаже по PQL:** более 3 агентов в проде, подключён SIEM или более 100 согласований в месяц. Партнёрства с аудиторами SOC 2 / ISO 42001 и MSSP.

**Лицензия:** Apache-2.0 для ядра, open core для коммерческих модулей. BSL не используем: Obot выпускает шлюз под MIT,\[56\] и ограничительная лицензия стала бы минусом.

---

## 13. Ценообразование

**Ориентиры рынка:**

| Продукт | Единица | Цена |
|---|---|---|
| Microsoft Agent 365 | пользователь в месяц | $15\[41\]\[57\] |
| Aembit | агент в месяц | $20\[58\] |
| Arcade.dev | вызов | $0,01\[52\] |
| Composio | вызовы | 100 000 бесплатно; Pro $29 в месяц\[53\] |
| Descope | согласие / токен | $0,05 сверх лимита\[46\] |
| Auth0 | MAU | бесплатно до 25 000\[43\] |
| Oso Cloud | — | от $149 в месяц\[59\] |

**Вывод.** Цена за пользователя наказывает B2C-сценарии. $0,01 за вызов слишком дорого для проверки, которая выполняется на каждом вызове. Оптимальна гибридная модель: платформенный сбор + агенты + вызовы с большим включённым объёмом + срок хранения журнала.

| Тариф | Цена | Включено |
|---|---|---|
| **Open Source** | $0 | Всё ядро, self-hosted без ограничений |
| **Cloud Free** | $0 | 3 агента, 100 000 вызовов в месяц, 7 дней журнала, Slack и вебхук |
| **Pro** | $79 в месяц | 20 агентов, 2 млн вызовов (далее $0,15 за 1 000), 90 дней, STS, все каналы |
| **Business** | от $899 в месяц | 200 агентов (далее $3 за агента), 25 млн вызовов, 1 год, EMA/XAA, SIEM, мультитенантность, SLA 99,95% |
| **Enterprise** | от ~$45 000 в год | Собственный контур / air-gapped, BYOK, регион ЕС, хранение до 7 лет, отчёты комплаенса, SLA 99,99% |

Отдельно — Scanner Pro для MSSP и аудиторов, от $299 в месяц.

Pro дешевле 20 агентов в Aembit ($400) и 20 пользователей в Agent 365 ($300). Все цены — гипотезы; проверить на интервью с 20–30 командами.

---

## 14. Регуляторика журналирования

| Режим | Требования | Ответ «Мандата» |
|---|---|---|
| **EU AI Act** | Регламент 2026/1744 (Omnibus) вступил в силу 27.07.2026. Высокорисковые системы Annex III — с 02.12.2027, Annex I — с 02.08.2028. Статья 50 — с 02.08.2026, статья 50(2) — с 02.12.2026. Статьи 9–15, включая статью 12 (автоматическая запись событий), не упрощены.\[60\]\[61\]\[62\]\[63\] Журналы хранятся не менее 6 месяцев | Автоматическая запись, approvals как доказательство надзора человека (статья 14), хранение ≥ 6 месяцев. Реальный запас времени — около 12 месяцев\[64\] |
| **GDPR** | Подотчётность, статьи 30 и 32, минимизация | Редактирование PII, режим метаданных, регион ЕС |
| **DORA** (с 17.01.2025) | Мониторинг ИКТ, отчётность об инцидентах, контроль третьих сторон | SIEM, детекции, kill-switch; сам «Мандат» готов к оценке как ИКТ-поставщик |
| **SOC 2** | Логический доступ и мониторинг (CC6/CC7), управление изменениями | Журнал доступа и журнал политик |
| **ISO/IEC 42001** | Роли, надзор, записи | Инвентарь агентов, журнал решений |
| **NIST** | Добровольные ориентиры | Маппинг на четыре фокуса NCCoE |

*Квалификация конкретной системы — ответственность клиента. «Мандат» даёт техническую доказательную базу.*

---

## 15. KPI (цели к 12-му месяцу)

- **North Star:** 1 млрд авторизованных и атрибутированных действий агентов в месяц.
- **Внедрение:** 8 000 звёзд на GitHub; 150 000 загрузок SDK в неделю; 25 000 просканированных серверов.
- **Активация:** ≥ 35% проектов включают `require_approval` или `deny` за 7 дней; медиана init → защищённый сервер ≤ 10 минут.
- **Качество:** p99 PDP < 5 мс; < 5% ложных срабатываний сканера.
- **Бизнес:** 400 платящих клиентов; ARR $1,5–2,5 млн; конверсия Free → Pro 3–5%; NRR > 120%.
- **Безопасность:** 0 компрометаций; 100% релизов подписаны.
- **Влияние:** < 2% проектов-пользователей без аутентификации (против 40,55% у Fudan).

---

## 16. Риски и меры

| Риск | Меры |
|---|---|
| IdP (Okta, Entra, Descope) бесплатно добавляют политики на вызовы | Нейтральность и мульти-IdP; глубина в политиках на аргументы и аудите; интеграция, а не конкуренция |
| Консолидация (PANW, Snowflake, Microsoft) | Движение снизу вверх; встраиваемость в их стеки через Envoy и Kong |
| Изменения спецификаций (DCR, ID-JAG, OAuth 2.1, OTel) | Слой абстракции, поддержка двух ревизий, участие в рабочих группах |
| Компрометация продукта или цепочки поставок | Раздел 8.3, bug bounty, независимый аудит |
| Задержка на критическом пути | Встроенный PDP, кэш, fail-modes на уровне инструментов |
| «Усталость от согласований» (ASI09) | Риск-скоринг, пакетирование, контекст, метрика времени на решение |
| OSS съедает выручку | Платная ценность — в хостинговом журнале, согласованиях, отчётах и SLA |
| Конкуренты с большим финансированием (Obot $35 млн, Runlayer $42 млн)\[34\] | Другой вход (библиотека), другой покупатель (разработчик), совместимость с их шлюзами |
| PII в аргументах вызовов | Редактирование в SDK, хеширование, BYOK, регион ЕС |

---

## 17. Открытые вопросы

1. Cedar или CEL в качестве языка политик? Сравнить на 20 реальных политиках.
2. Хранить ли downstream-токены (как Token Vault) или всегда делегировать хранение IdP?
3. Насколько надёжен taint-трекинг без ложных блокировок?
4. Как кэшировать токены при лимите Okta XAA в 250 ID-JAG в месяц?
5. Когда интегрироваться с официальным MCP Registry (пока в preview)?
6. Какой формат межагентной (A2A) цепочки станет стандартом: вложенный `act`, Transaction Tokens или AIMS?
7. Какая единица цены ценнее для клиента: агенты, вызовы или срок хранения?
8. Нужна ли регулируемым клиентам квалифицированная метка времени eIDAS?
9. Перепроверить выборку Zuplo (по странице отчёта — «nearly 100» респондентов, показатель 50% — на N=50 строителей) и трактовку 119 OAuth-серверов у Fudan.

---

## Ограничения

- Оценки Natoma (около $110 млн) и «$700M-class» для Portkey взяты из вторичных источников; для Portkey приоритетна отчётность PANW в SEC.\[36\]\[37\]\[38\]
- Данные о пакете и сроке без патча для CVE-2026-32211 — из вторичных источников.\[6\]
- «200 000 серверов» — оценка OX Security.
- Цены конкурентов быстро меняются: Composio сменил тарифы 15.08.2026,\[53\] часть цен Stytch и Arcade подтверждена только сторонними снапшотами.
- Цены, KPI и критерии выхода фаз — гипотезы для проверки.

## Sources

1. [MCP Server Security Best Practices to Prevent Risk](https://www.descope.com/blog/post/mcp-server-security-best-practices)
2. [AI Agent Identity Sprawl: The Enterprise Authorization Crisis](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-identity-sprawl-authorization-202/)
3. [More Than Two-Thirds of Organizations Cannot Clearly Distinguish AI Agent from Human Actions as Over-Privileged Access Becomes Widespread, Cloud Security Alliance Study Finds](https://www.businesswire.com/news/home/20260324161665/en/More-Than-Two-Thirds-of-Organizations-Cannot-Clearly-Distinguish-AI-Agent-from-Human-Actions-as-Over-Privileged-Access-Becomes-Widespread-Cloud-Security-Alliance-Study-Finds)
4. [A First Measurement Study on Authentication Security in Real-World Remote MCP Servers](https://arxiv.org/pdf/2605.22333)
5. [CVE-2026-32211 - Azure MCP Server Information Disclosure Vulnerability](https://cvefeed.io/vuln/detail/CVE-2026-32211)
6. [Azure DevOps MCP Server — Microsoft's Official AI Bridge to Work Items, Repos, Pipelines, and Test Plans — ChatForest](https://chatforest.com/reviews/azure-devops-mcp-server/)
7. [Security Update: CVE-2026-30623 — Command Injection via Anthropic's MCP SDK](https://docs.litellm.ai/blog/mcp-stdio-command-injection-april-2026)
8. [200,000 MCP servers expose a command execution flaw that Anthropic calls a feature](https://venturebeat.com/security/mcp-stdio-flaw-200000-ai-agent-servers-exposed-ox-security-audit)
9. [MCP Security Checklist for Marketers: 7 Questions Before You Install Any MCP Server](https://www.1clickreport.com/blog/mcp-security-checklist-marketers-2026)
10. [MCP Horror Stories: The GitHub Prompt Injection Data Heist](https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/)
11. [Defense in Depth for MCP Servers](https://supabase.com/blog/defense-in-depth-mcp)
12. [Supabase MCP 'lethal trifecta' — full SQL DB exfiltration via stored prompt injection — Vibe Coding · Security Issue Tracking](https://www.pranavaraparla.com/vibe-coding-security/advisories/2025-07-supabase-mcp-lethal-trifecta.html)
13. [LiteLLM supply chain compromise](https://www.giskard.ai/knowledge/litellm-supply-chain-attack-2026)
14. [LiteLLM hit by second supply chain attack this year, users urged to rotate credentials - Help Net Security](https://www.helpnetsecurity.com/2026/10/22/litellm-compromised-supply-chain-attack-pypi-docker/)
15. [Summary of Comments on the Concept Paper — NCCoE Agentic AI Identity and Authorization Project Resource Hub documentation](https://pages.nist.gov/nccoe-ai-identity/summary-of-comments.html)
16. [MCP OAuth: How MCP Authentication Works (2026) — Scalar](https://scalar.com/learn/mcp/mcp-oauth)
17. [zuplo.com](https://zuplo.com/learn/mcp/glossary/credentials.md)
18. [Inside the ID-JAG: How enterprise-managed authorization actually works — WorkOS](https://workos.com/blog/mcp-enterprise-managed-authorization-id-jag)
19. [DEV Community](https://dev.to/webofmike/mcp-cross-app-access-explained-the-id-jag-exchange-on-the-wire-4217)
20. [Enterprise-Managed Authorization - Model Context Protocol](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization)
21. [cross app access](https://docs.getbifrost.ai/mcp/auth/cross-app-access)
22. [Where AI Agent Authorization Standards Stand - RFCs, IETF Working Group Documents, Individual Drafts, and Specifications from Other Bodies](https://hidekazu-konishi.com/entry/where_ai_agent_authorization_standards_stand.html)
23. [Integrating with Model Context Protocol (MCP)](https://keycloak.org/securing-apps/mcp-authz-server)
24. [ID-JAG, Transaction Tokens, WIF: The Three Layers of AI Agent Auth - DEV Community](https://dev.to/kanywst/the-three-layers-of-ai-agent-authentication-what-id-jag-transaction-tokens-and-wif-actually-1mbk)
25. [draft-oauth-ai-agents-on-behalf-of-user-02](https://datatracker.ietf.org/doc/html/draft-oauth-ai-agents-on-behalf-of-user-02)
26. [Last updated: September 14, 2026](https://www.dash0.com/knowledge/opentelemetry-genai-semantic-conventions-explained)
27. [OpenTelemetry's GenAI semantic conventions are NOT stable yet — here's what actually shipped in 2026 - DEV Community](https://dev.to/azena-ai/opentelemetrys-genai-semantic-conventions-are-not-stable-yet-heres-what-actually-shipped-in-2026-3mke)
28. [38% of MCP servers have no auth -- inside the OWASP MCP Top 10 - DEV Community](https://dev.to/kenimo49/38-of-mcp-servers-have-no-auth-inside-the-owasp-mcp-top-10-hm)
29. [OWASP Top 10 for Agentic Applications 2026](https://cycode.com/blog/owasp-top-10-agentic-applications/)
30. [NIST AI Agent Authorization: Five Asks Mapped to Kubernetes - ARMO](https://www.armosec.io/blog/nist-ai-agent-identity-authorization/)
31. [Federal Agentic AI Security: NIST’s Emerging Standards Initiative](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-standards-federal-framework/)
32. [Obot AI](https://allthingsai.org/ai-industry/companies/obot-ai)
33. [Revolutionary MCP AI Security Startup Runlayer Secures \$11M from Keith Rabois, Protects 8 Unicorns](https://cryptorank.io/news/feed/f27b6-runlayer-mcp-ai-security)
34. [Runlayer Raises \$30M Series A for Enterprise MCP Platform - TAMradar Funding Rounds Signals](https://www.tamradar.com/funding-rounds/runlayer-series-a-30m)
35. [Snowflake Announces Intent to Acquire Natoma, Providing Secure Connectivity For The Agentic Enterprise](https://www.snowflake.com/en/news/press-releases/snowflake-announces-intent-to-acquire-natoma-providing-secure-connectivity-for-the-agentic-enterprise/)
36. [Snowflake buys Natoma for about 110 million dollars to govern agent access to data](https://startwithidentity.com/blog/2026-05-27-snowflake-to-acquire-natoma-mcp-agent-governance/)
37. [Palo Alto Networks makes a \$700M-class AI bet on Portkey gateway - The New Stack](https://thenewstack.io/palo-alto-portkey-ai-gateway/)
38. [Palo Alto Networks Inc - Form 10-K - FY2026](https://www.sec.gov/Archives/edgar/data/0001327567/000132756726000023/panw-20260731.htm)
39. [Palo Alto Networks Inc - Form 10-Q - FY2026](https://www.sec.gov/Archives/edgar/data/0001327567/000132756726000015/panw-20260430.htm)
40. [Palo Alto Networks (PANW) Completes Acquisition of AI Gateway Provider Portkey](https://finance.yahoo.com/sectors/technology/articles/palo-alto-networks-panw-completes-112329938.html)
41. [Microsoft Entra Agent ID vs Keycloak for AI Agent Identity](https://skycloak.io/blog/entra-agent-id-vs-keycloak-ai-agent-identity/)
42. [Agent 365 Licensing: What It Covers and Costs](https://samexpert.com/agent-365/)
43. [AI Agent Authentication Platforms Compared (2026)](https://www.agentmail.to/blog/ai-agent-authentication-platforms-compared-2026)
44. [Auth0 Review (2026): Pricing, Pros & Cons, Verdict](https://www.siit.io/tools/trending/auth0-review)
45. [Pricing](https://www.descope.com/pricing)
46. [Descope M2M & Agentic Identity Pricing Update](https://www.descope.com/blog/post/m2m-agentic-identity-pricing-update)
47. [Stytch AI search visibility, competitors, reviews, and pricing](https://devtune.ai/verticals/agent-authentication-identity-for-ai/stytch)
48. [Workload IAM & Non-Human Identity FAQ - Aembit](https://aembit.io/faq/)
49. [Pricing for Non-Human IAM - Aembit](https://aembit.io/pricing/)
50. [Top 21 Authorization Systems and Tools for 2025](https://www.osohq.com/learn/best-authorization-tools-and-software)
51. [Best AI Authorization Tools and Software in 2026: A Buyer's Guide](https://www.plainid.com/blog/best-ai-authorization-tools/)
52. [Pricing - Arcade.dev](https://www.arcade.dev/pricing/)
53. [Pricing | Composio](https://composio.dev/pricing)
54. [The Zuplo State of MCP Report - Zuplo](https://zuplo.com/blog/mcp-survey)
55. [Implement Client ID Metadata Documents (CIMD) for MCP Authorization (SEP-991)](https://gitlab.com/gitlab-org/gitlab/-/issues/585069)
56. [Obot MCP Gateway](https://obot.ai/mcp-gateway/)
57. [Agent 365 Licensing: What AI Agents Will Actually Cost You](https://licenseq.com/agent-365-licensing/)
58. [Aembit IAM for Agentic AI Is Now Generally Available](https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/)
59. [Best Permit.io Alternatives & Competitors 2025](https://www.osohq.com/learn/permitio-alternatives)
60. [How the Digital Omnibus changes the EU AI Act Timeline for PV AI Systems](https://pvtech.substack.com/p/how-the-digital-omnibus-changes-the)
61. [AI Act: obligations in force and delays under omnibus 2026/1744 — ActuIA](https://www.actuia.com/en/news/ai-act-obligations-in-force-and-delays-under-omnibus-2026-1744/)
62. [EU AI Act omnibus: the new high-risk deadlines explained](https://verifywise.ai/blog/eu-ai-act-omnibus-what-changed)
63. [EU AI Act Deadlines After the Digital Omnibus: What Applies From December 2026 to August 2028 - Technology Org](https://www.technology.org/2026/10/13/eu-ai-act-deadlines-after-the-digital-omnibus-what-applies-from-december-2026-to-august-2028/)
64. [EU AI Act Delay Is Final: High-Risk Moves to Dec 2027](https://accuroai.co/blog/eu-ai-act-delayed-december-2027-digital-omnibus)
