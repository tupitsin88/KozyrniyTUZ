# Карта требований и проверок

Документ связывает требования безопасности `SR-01`–`SR-10`, угрозы `T-01`–`T-10` и решения `D-01`–`D-04` с существующими автоматизированными проверками. Наличие теста в таблице означает, что соответствующий сценарий есть в коде тестов; это не означает, что тест запускался в текущем окружении.

## Требования и автоматизированные проверки

| Требование | Угрозы и решения | Основные автоматизированные проверки | Граница текущей проверки |
| --- | --- | --- | --- |
| SR-01 — доступ к материалам клуба | T-01, T-04; D-02, D-03 | `TestPostgresMaterialsAndArchiveLifecycle` | Проверяет API и PostgreSQL; браузерный сценарий отдельно не автоматизирован |
| SR-02 — доступ к заявкам | T-02, T-04; D-02 | `TestPostgresApplicationAndMembershipLifecycle` | Проверяет владельца, администратора клуба и прямое чтение по ID |
| SR-03 — архивирование клуба | T-03, T-04; D-01, D-02, D-03 | `TestPostgresMaterialsAndArchiveLifecycle` | Проверяет полномочия, сохранение связанных строк и прекращение доступа |
| SR-04 — рассмотрение заявок | T-05; D-02, D-03 | `TestPostgresApplicationAndMembershipLifecycle` | Проверяет повторное и конкурирующие решения, атомарность членства |
| SR-05 — управление членством | T-06, T-04; D-02, D-03 | `TestPostgresApplicationAndMembershipLifecycle`, `TestPostgresMaterialsAndArchiveLifecycle` | Проверяет границы клуба, роли и ручное изменение членства |
| SR-06 — изменение материалов | T-07, T-04; D-02, D-03 | `TestPostgresMaterialsAndArchiveLifecycle` | Проверяет чтение, создание, изменение, чужие клубы и архивирование |
| SR-07 — права создателя клуба | T-08; D-03 | `TestPostgresClubAndProfileLifecycle` | Проверяет, что исходные полномочия и членство выдаются текущему создателю |
| SR-08 — создание заявки от своего имени | T-09; D-03 | `TestPostgresApplicationAndMembershipLifecycle` | Проверяет поля владельца и статуса, роль, архив, членство, дубликаты и гонку подачи |
| SR-09 — подлинность пользователя и роли | T-03; D-01, D-02 | `TestPostgresAuthenticationLifecycle`, `TestRegistrationRequiresTrustedOriginAndStrictJSON`, `TestPostgresApplicationAndMembershipLifecycle` | Проверяет сессию, роль регистрации, Origin/CSRF и подмену защищённых полей |
| SR-10 — защита пароля | T-10; D-04 | `TestHashPasswordUsesUniqueArgon2idSalt`, `TestVerifyPasswordRejectsUnsupportedOrUnsafeVerifier`, `TestUpgradeParametersNeverReduceAnExistingParameter`, `TestPostgresAuthenticationLifecycle` | Проверяет формат, соль, проверку, безопасный отказ и обновление параметров; отдельной проверки журналов на отсутствие секрета нет |

## Остальные проверки

- `TestPostgresAuthenticationLifecycle` проверяет bootstrap SuperUser, Argon2id-verifier, ротацию и отзыв сессий, idle- и absolute-expiration.
- `TestPostgresApplicationAndMembershipLifecycle` включает параллельную подачу и параллельное решение заявок, проверку отката и повторов после deadlock.
- `TestPostgresMaterialsAndArchiveLifecycle` проверяет гонку создания материала с архивированием.
- Тесты `cmd/server` проверяют health endpoint, методы доступа к нему и выдачу встроенных файлов с заголовками безопасности.
- Тесты `cmd/server` проверяют пределы HTTP-запросов и штатную остановку сервера после отмены контекста.
- Unit-тесты конфигурации и HTTP-обработчиков проверяют безопасные настройки, строгий JSON, Origin/CSRF и форматы идентификаторов.
- `TestTextLengthLimitsCountUnicodeCodePoints`, `TestDecodeJSONAcceptsMaximumUnicodeText`, `TestDecodeJSONRejectsOversizedBody` и Unicode-границы в `TestNormalizeLoginAndValidatePassword` проверяют серверные пределы текста и пароля, приём 16 000 Unicode-символов и ограничение размера запроса.

## Известные пробелы автоматизации

- PostgreSQL-интеграционные тесты пропускаются, если `AUTH_TEST_DATABASE_URL` не задана. Workflow `.github/workflows/ci.yml` запускает их с отдельным экземпляром PostgreSQL; полный локальный запуск описан в [PROJECT.md](PROJECT.md#10-локальный-запуск).
- В репозитории нет браузерных end-to-end тестов. Проверка сохранённого XSS-payload на реальном DOM остаётся ручным приёмочным сценарием.
- Не автоматизирована проверка журналов на отсутствие открытых паролей и session-токенов.
- Безопасность новых маршрутов зависит от наличия аутентификации и SQL-политики в обработчике. При добавлении маршрута нужно добавлять отрицательный сценарий интеграционного теста.
- `go test ./...` без тестовой строки подключения не подтверждает PostgreSQL-сценарии. Для проверки SQL и миграций смотри успешный запуск интеграционных тестов в CI, а не только наличие тестовых функций.

## Локальные проверки

Для проверки сервера и интерфейса из корня репозитория:

```powershell
npm ci
npm run build
go test ./...
go vet ./...
go build ./cmd/server
```

Для выполнения PostgreSQL-интеграционных тестов перед `go test ./...` задайте `AUTH_TEST_DATABASE_URL` на отдельную тестовую базу PostgreSQL. Не используйте для интеграционных тестов базу с нужными пользовательскими данными.

CI настроен в `.github/workflows/ci.yml`: он собирает клиент и сервер, запускает `go vet ./...` и выполняет `go test ./...` с отдельным PostgreSQL 18, поэтому интеграционные тесты не пропускаются.

В локальном запуске этой ветки `npm run build`, `go test ./...`, `go vet ./...` и `go build ./cmd/server` завершились успешно. `AUTH_TEST_DATABASE_URL` в окружении не была задана, а PostgreSQL на `127.0.0.1:5432` недоступен, поэтому локальные PostgreSQL-интеграционные сценарии были пропущены; это не подтверждает подключение к реальному экземпляру PostgreSQL.
