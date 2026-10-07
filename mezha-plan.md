# Mezha — план реалізації

> **A boundary, not a matcher.** Governance і memory plane для проєктів Claude Code.

Версія документа: 0.1 · Дата: 2026-10-07 · Статус: чернетка для ADR-0001

---

## 1. Назва

**Mezha** (укр. *межа* — границя, лінія, яку сусіди поважають).

Дві тези інструмента, з яких походить назва:

1. Безпека агента — це **межа** (OS, credentials, сервер), а не матчер команд.
2. Знання агента — це те, що лишається **за межею сесії** (skills, rules, памʼять після dreaming).

Ідентифікатори:

| Що | Значення |
|---|---|
| Бінарник / crate | `mezha` |
| Plugin для Claude Code | `mezha@<marketplace>` |
| Префікс змінних середовища | `MEZHA_` |
| Директорія стану | `.claude/.mezha-state.json` |
| Слоган README | *A boundary, not a matcher* |

Перевірка колізій (пошук GitHub / crates.io / npm, жовтень 2026):

| Кандидат | Результат |
|---|---|
| Praxis | зайнято: crate `praxis` (фреймворк агентів), `prx`, `coe0718/praxis` |
| Nomos | зайнято: кілька агентних фреймворків, CLI Google Config Sync, Ruby PR-тул |
| Stele | зайнято: crate `stelegen` ставить бінарник `stele` |
| Mnema | зайнято: чотири memory-проєкти для агентів |
| **Mezha** | **колізій не знайдено** |

Перед публікацією: `cargo search mezha`, `npm view mezha`, перевірка GitHub org.

Запасні варіанти: **Kordon** (кордон; англ. читається як *cordon*), **Keelson** (кільсон — балка, що тримає кіль).

---

## 2. Принципи (не обговорюються в коді)

1. **Межа важливіша за матчер.** Кожна функція безпеки або є OS/серверною межею, або в документації та у виводі `verify` позначена *advisory*.
2. **Кожен dream — це diff**, який читає людина. Памʼять ніколи не мутується мовчки.
3. **Хуки fail-closed.** Відсутність бінарника блокує, а не пропускає.
4. **Spec — єдине джерело.** Руками правляться лише файли, які Mezha позначає як ваші (відбитки файлів).
5. **Два режими ОС явні:** `full` (macOS, Linux, WSL2) і `native-windows` (деградований і чесний).
6. **Метрики вбудовані.** Інструмент сам доводить, що окупається; якщо ні — відповідний шар вимикається.
7. **Клас памʼяті `phi`** блокує project-scope і вимагає очищення транскриптів.
8. **Не генератор.** Wizard ролей, провайдери, OpenCode-ціль, dynamic workflows — поза v0.

---

## 3. Архітектура: Rust workspace

```
mezha/
├── crates/
│   ├── mezha-spec/      # схема TOML, валідація, Rule of Two
│   ├── mezha-render/    # MiniJinja → .claude/ і plugin, відбитки, бекапи
│   ├── mezha-hooks/     # усі гейти в Rust, номер протоколу, fail-closed
│   ├── mezha-verify/    # тести межі, JSON-звіт, exit 1 для CI
│   ├── mezha-broker/    # approve як видача можливості (loopback helper, токени)
│   ├── mezha-memory/    # dream-пайплайн, crystallize, injection-скан, PHI-режим
│   ├── mezha-metrics/   # SQLite, A/B-раннер, звіти
│   └── mezha-cli/       # clap, команди
├── templates/           # шаблони .claude/ (editable, крім gate-protocol)
├── tests/
│   ├── e2e_hooks.rs     # команди хуків дослівно з settings.json
│   ├── boundary.rs      # verify має фейлитись на зламаній межі
│   └── memory.rs        # детермінований dream на фікстурах
└── docs/adr/
```

### 3.1 mezha-spec
- TOML через `serde`, версія схеми, міграції старих state-файлів.
- Компайл-перевірка **Rule of Two**: агент з `untrusted_input` + `private_data` + `external_action` не збирається без явного `human_gate`, і тоді в згенерованій документації гейт позначений *advisory*.
- Валідація імен (безпечні для файлів і `@mentions`), унікальність без урахування регістру.

### 3.2 mezha-render
- Генерує: `.claude/agents/*.md`, `.claude/skills/*/SKILL.md`, `.claude/rules/*.md` (з `paths`), `settings.json`, хуки, output style, `CLAUDE.md` (лише ростер і протокол), `.gitattributes` (LF для `.claude/**`), `.worktreeinclude`.
- Plugin-вихід: `.claude-plugin/plugin.json`, `marketplace.json`, `hooks/hooks.json`, release workflow.
- Відбитки файлів, бекапи в `.mezha-backup/<ts>/`, `--dry-run` з diff. Переноситься з ocgen.

### 3.3 mezha-hooks
- Гейти: approval, worker/confidence, task, plan, risk, loop guard, WebFetch guard, config audit.
- Команда хука — **прямий виклик бінарника** (`mezha hook <name>`), без shell-обгортки; на Windows маршрутизація `"shell": "powershell"` per-hook.
- Рішення: **без sh-двійників**. Плюс — один код, Windows без Git Bash, fail-closed природно. Мінус — кожна машина й CI встановлюють `mezha`.
- Номер протоколу хуків; невідповідність версії = блок, не пропуск.

### 3.4 mezha-verify (тести межі, не матчера)
Перевірки, кожна з fail/warn:
- sandbox увімкнений (у режимі `full` — fail, якщо ні);
- `git push --dry-run` зсередини sandbox падає з auth error (credentials недосяжні);
- keychain / Credential Manager недоступний агенту;
- branch protection увімкнена (через `gh api repos/:owner/:repo/branches/<main>/protection`), required reviews від code owners;
- хуки не підмінені (відбиток збігається з state);
- жоден рівень settings (user, project, local, managed) не послаблює гейт;
- dreamer не має `Bash` і має права запису лише в `.claude/agent-memory/`;
- `.claude/` відстежується git; `CLAUDE.local.md` у `.gitignore`;
- `claude plugin validate` проходить.
- Вихід: людський текст + `--json`; `exit 1` на будь-якому fail.

### 3.5 mezha-broker
- `mezha approve [--minutes N]` відмовляється працювати під Claude Code і без терміналу (UX-бар'єр), але **межа** — не ця перевірка, а:
  - loopback credential helper на `127.0.0.1` з випадковим токеном;
  - короткоживучий токен (GitHub App installation token зі скоупом на репо), expiry = відкликання;
  - сховище approvals поза проєктом, недоступне на запис із sandbox;
  - у `native-windows`: окремий локальний акаунт агента з порожнім Credential Manager, NTFS ACL на сховище й `.git/hooks`.
- Альтернатива без брокера (документована як найміцніша): агент комітить, людина пушить.

### 3.6 mezha-memory
- **Inbox collector:** копіює останні N транскриптів з `~/.claude/projects/<project>/` у git-ігнорований `.claude/dream-inbox/`, збирає `escalations.md`, вердикти adversary, леджери `/inquire`, auto memory.
- **Dreamer:** субагент (`sonnet`), tools `Read, Grep, Glob, Write, Edit`, без `Bash`, `disable-model-invocation: true`, запис лише в `.claude/agent-memory/<role>/`.
- **Рольові політики** в тілі dreamer-а:
  - implementer: «уникай X, бо Y (бачено N разів)»;
  - explorer: лише Verified-факти з `file:line`; Inferred і Stale викидаються;
  - adversary: лише патерни атак, що знайшли реальні баги; **ніколи** правила «це можна пропустити».
- **Вихід:** PR-diff, changelog у кінці файлу памʼяті, посилання на ADR замість переказу.
- **Governance:** CODEOWNERS на `.claude/agent-memory/`, аудит змін, injection-скан перед мержем, rollback через git.
- **PHI-режим:** scope лише `local`, очищення транскриптів за патернами, заборона project-memory в репо клієнта.
- **Бюджети:** індекс памʼяті до 200 рядків / 25 КБ; dreamer стискає, не дописує.
- **Crystallize:** записи, що пережили три dream-и поспіль без змін → кандидат на knowledge skill або path-scoped rule у вигляді PR.

### 3.7 mezha-metrics
- Локальна SQLite: раунди переробки на задачу, UNRESOLVED на тиждень, вартість сесії, частка dream-diff-ів, злитих без правок.
- A/B-раннер: `claude -p` на наборі задач із підключеною памʼяттю і з порожньою; звіт.

### 3.8 mezha-cli
```
mezha init                      # створити spec у поточному репо
mezha compile [--plugin]        # spec → .claude/ (і plugin)
mezha diff                      # що зміниться
mezha apply [--yes]             # записати з бекапами
mezha verify [--json]           # тести межі; exit 1 у CI
mezha approve [--minutes N|--status|--revoke]
mezha dream [--role r] [--since 7d]
mezha crystallize               # памʼять → кандидати skill/rule
mezha metrics [--ab tasks.toml]
mezha doctor [--dry-run]
mezha skill add|edit|eval
mezha rule add
mezha hook <name>               # викликається Claude Code
```

---

## 4. Spec v1 (`mezha.toml`)

```toml
[project]
name = "client-x"
os_mode = "full"            # full | native-windows
check = "cargo test --workspace"
languages = { instructions = "English", answers = "Ukrainian" }

[policy]
sandbox = true
egress_allow = ["github.com", "crates.io", "pypi.org"]
permissions_ask = ["git push", "terraform apply", "docker push"]
deny_reads = [".env", "*.pem", "*.key", "*.tfstate"]

[memory]
dream_schedule = "nightly"    # nightly | manual | cron
default_scope = "project"
phi_repos = ["client-x-phi"]  # для них scope = local, очищення обовʼязкове

[agent.implementer]
model = "sonnet"
tools = ["Read", "Edit", "Write", "Bash(cargo *)"]
skills = ["rust-conventions", "db-migrations"]
rule_of_two = ["untrusted_input", "private_data"]   # external_action заборонено компілятором
memory = { scope = "project", class = "no-phi" }
max_turns = 60

[agent.adversary]
model = "opus"
effort = "high"
tools = ["Read", "Grep", "Glob", "Bash(cargo test *)"]
disallowed_tools = ["Edit", "Write", "NotebookEdit"]
rule_of_two = ["untrusted_input", "private_data"]
memory = { scope = "project", dream_policy = "attack-patterns-only" }
max_turns = 40

[skill.rust-conventions]
preset = "knowledge"
description = "Error handling, logging and test conventions for this Rust workspace. Use when writing, changing or reviewing Rust code."
paths = ["**/*.rs", "Cargo.toml"]
user_invocable = false

[skill.release]
preset = "command"
description = "Cut a release: checks, version bump, changelog, git tag. Use when the user asks to release or tag a version."
arguments = ["version"]
allowed_tools = ["Bash(cargo clippy *)", "Bash(cargo test *)", "Bash(git describe *)", "Bash(git tag *)"]

[rule.terraform]
paths = ["infra/**/*.tf"]
max_lines = 30
```

Правила компілятора:
- `rule_of_two` з трьома властивостями → помилка збірки з поясненням і підказкою, яку властивість зняти; збирається лише з `human_gate = "advisory"`.
- `rule` без `paths` → попередження (поводиться як CLAUDE.md, оплачується щоходу).
- `skill` з `preset = "command"` → автоматично `disable-model-invocation: true`; нескоуплений `Bash` у `allowed_tools` → fail.
- `skill` з `preset = "knowledge"` → `user-invocable: false` за замовчуванням; опис < 40 символів або без «Use when» → fail.
- `description` + `when_to_use` > 1536 символів → fail; CLAUDE.md > 200 рядків → warn.
- `memory.class = "phi"` → `scope = "local"` примусово; project-scope → помилка.

---

## 5. Фази

| Фаза | Тривалість | Зміст | Definition of Done |
|---|---|---|---|
| 0 | 1 тиж. | Імʼя на реєстрах, репо, ADR-0001, CI-матриця, інвентар переносу з ocgen | ADR прийнятий; CI зелений на 4 платформах з порожнім workspace |
| 1 | 3–4 тиж. | spec, compile, plugin, verify, хуки fail-closed | `compile` → проєкт проходить `claude plugin validate`; `verify` фейлиться на 5 сценаріях зламаної межі і проходить на чистому; e2e-хуки з settings.json |
| 2 | 3 тиж. | Memory plane: dream, governance, розклад, PHI, базові метрики | dream на реальному репо дає PR, прийнятий без правок ≥ 1 раз; verify перевіряє dreamer; A/B-раннер відпрацьовує 10 задач |
| 3 | 2 тиж. | Crystallize, eval skills, лінтери бюджетів, path-scoped rules, CLAUDE.local.md | 1 crystallize-PR злитий; eval показує різницю зі skill-ом і без на 3 реальних промптах |
| 4 | 2 тиж. | native-windows: окремий акаунт + ACL, PowerShell-хуки, portable skills, інсталятор з WSL2 як дефолтом | verify на native Windows друкує «sandbox відсутній, гейт advisory», фейлиться без branch protection; хук без бінарника блокує |
| 5 | 2 тиж. | Dogfood на 2 клієнтських репо, A/B 14 днів | go/no-go за метриками (розділ 7) |

Разом: **11–13 тижнів** для однієї людини з урахуванням переносу з ocgen.

### 5.1 Фаза 0 — детально
- Застовпити `mezha` на crates.io, npm (placeholder), GitHub.
- ADR-0001 «Mezha — governance і memory, не генератор»: поза v0 — wizard ролей, провайдери, OpenCode-ціль, dynamic workflows, власна оркестрація.
- Інвентар переносу з ocgen: Rust-хуки, doctor з відбитками й бекапами, verify-каркас, `/inquire` з HTML-леджером, `/intent` (ADR, approvers, CODEOWNERS), поділ мов, `install.sh`/`install.ps1`, release workflow, система override-шаблонів (спрощена).
- CI-матриця: macOS (arm64), Linux (x86_64, arm64), Windows native, Windows WSL2.

### 5.2 Фаза 1 — детально
- `mezha-spec`: схема, валідація, 3 тести на відмову збірки (Rule of Two, нескоуплений Bash, phi + project).
- `mezha-render`: шаблони `.claude/`, plugin, відбитки, `--dry-run`.
- `mezha-hooks`: перенос з ocgen, видалення sh-двійників, fail-closed тест (бінарник відсутній → exit 2).
- `mezha-verify`: 9 перевірок з розділу 3.4; boundary-тести навмисно ламають межу й очікують fail.
- Документація: README із розділом «Що є межею, а що advisory» першим.

### 5.3 Фаза 2 — детально
- Inbox collector, dreamer-шаблон, рольові політики, PR-вихід.
- Розклад: scheduled task Claude Code, cron, Windows Task Scheduler; headless-запуск з явними allow-правилами на `Write(.claude/agent-memory/**)`, без auto mode.
- Injection-скан: евристики на інструктивні конструкції у транскриптах і в diff памʼяті; підозріле → блок мержу з поясненням.
- PHI-режим: очищення за патернами (ідентифікатори, дати народження, контакти, MRN), обовʼязкове для репо зі списку `phi_repos`.
- Метрики: парсер транскриптів і `escalations.md` → SQLite.

### 5.4 Фаза 3 — детально
- Crystallize: детектор стабільності (3 dream-и без змін), генерація кандидата skill/rule, PR.
- `mezha skill eval`: baseline зі skill-ом і без у свіжій сесії, hit rate тригера на should/should-not промптах (обгортка над skill-creator або власний раннер).
- Лінтери бюджетів у `verify`.
- `mezha rule add` з обовʼязковим `paths`.

### 5.5 Фаза 4 — детально
- Режим `native-windows`: скрипт створення акаунта агента, ACL на сховище approvals і `.git/hooks`, перевірка в verify.
- Хуки: per-hook `"shell": "powershell"`, бінарник напряму.
- Portable skills: без `!`-інʼєкції або з `shell: powershell` і врахуванням іншого набору «мʼяких» exit-кодів.
- Інсталятор: WSL2 — рекомендований шлях; native — явний вибір із попередженням.

---

## 6. Тестова стратегія

| Шар | Що перевіряє | Інструмент |
|---|---|---|
| Unit | spec, render, лінтери | `cargo test` |
| E2E хуків | команди хуків дослівно з `settings.json`, подія на stdin, маршрутизація за matcher | `tests/e2e_hooks.rs` |
| Boundary | verify фейлиться, коли межа зламана (sandbox off, токен підкладений, protection вимкнена, хук підмінений) | `tests/boundary.rs` |
| Memory | детермінований dream на фікстурах; injection-скан ловить підкладений інструктаж; phi-режим відкидає транскрипт із PHI | `tests/memory.rs` |
| Cross-OS | 4 платформи; на WSL2 окремо: sandbox стартує, а не мовчки падає у no-sandbox | CI matrix |
| Plugin | `claude plugin validate`, `claude plugin eval` на skills | CI |

---

## 7. Метрики і go/no-go

Збираються автоматично (`mezha metrics`):

| Метрика | Ціль після dogfood |
|---|---|
| Вартість на задачу | не гірше голого Claude Code більш ніж на 30% |
| Раунди переробки на задачу | менше, ніж без памʼяті |
| UNRESOLVED на тиждень | менше, ніж без памʼяті |
| Повернення з людського review | менше |
| Частка dream-diff-ів, злитих без правок | ≥ 50% після місяця (інакше рольові політики погані) |
| Precision/recall тригера skills | precision ≥ 0.8 на should/should-not наборі |
| False positive у verify | 0 (кожен — баг) |

**Go:** повернення з review і «зробив не те» кращі, вартість не гірша ніж на 30%.
**No-go:** лишити `verify` + `broker` як окремий маленький інструмент; memory plane закрити.

---

## 8. Ризики і мітигації

| Ризик | Мітигація |
|---|---|
| Churn Claude Code (дефолти, формати, хуки) | тонкий адаптерний шар; номер протоколу; матриця підтримуваних версій у verify з попередженням про непротестовану |
| Anthropic додає dreaming у CLI | інтерфейс `mezha dream` лишається, бекенд стає адаптером — це прийнятний результат |
| Хуки й MCP поза sandbox | verify попереджає; MCP-сервери під окремою ідентичністю |
| Native Windows без sandbox | режим `native-windows` з ACL і обовʼязковим branch protection; гейт позначений advisory |
| Памʼять як канал prompt injection | PR-diff, injection-скан, CODEOWNERS, rollback |
| PHI у git-історії | local scope, очищення, заборона project-memory для phi-репо |
| Прокрастинація в генератор | ADR-0001; правило «жодної нової команди без boundary- або memory-обґрунтування» |
| Сліпа довіра до verify | кожен false positive — баг з найвищим пріоритетом |

---

## 9. Перший тиждень

| День | Задача |
|---|---|
| 1–2 | репо, workspace, ADR-0001, CI-матриця, імʼя на реєстрах |
| 3–4 | `mezha-spec` з валідацією Rule of Two і трьома тестами на відмову збірки |
| 5 | перенос `mezha-hooks` з ocgen, видалення sh-двійників, fail-closed тест |
| Кінець тижня | `compile` дає порожній, але валідний `.claude/` і один хук, який блокує `git push` без `approve` |

---

## 10. Що переноситься з ocgen як є

- Rust-хуки з номером протоколу.
- `doctor` з відбитками файлів, бекапами, per-file review.
- Каркас `verify` (злиття settings, перевірка хуків, статуслайн, `claude plugin validate`).
- `/inquire` з леджером і HTML-переглядачем.
- `/intent` з ADR, approvers, CODEOWNERS, тон-чеком.
- Поділ мов інструкцій і відповідей.
- `install.sh`, `install.ps1`, Scoop-маніфест, release workflow із `SHA256SUMS`.

Що **не** переноситься: wizard, провайдери, OpenCode-ціль, пʼятиагентний дефолт, sh-двійники хуків, текстовий гейт як «security».
