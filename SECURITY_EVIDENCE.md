# Свидетельство S06–S07: решение по заявке клуба

## Проверяемое свойство

Цепочка проекта: `T-05 → SR-04 → D-02/D-03`.

Только действующий Administrator активного клуба может принять или отклонить
`pending`-заявку этого клуба. Запрещённая попытка не должна раскрывать текст
заявки и изменять её статус, `administrator_id`, `decided_at` или членство.
Разрешённое решение должно сохраниться согласованно: при `approved` вместе со
статусом создаётся членство, при `rejected` новое членство не появляется.

Это подтверждение уже обеспеченного свойства, а не цепочка исправления
найденного дефекта. Искусственная уязвимость в проект не вносилась.

## Механизм

- Начальная матрица связей фиксирует `T-05 → SR-04 → D-02/D-03` в
  [SECURITY_DESIGN.md](SECURITY_DESIGN.md).
- `D-02` требует серверной объектной авторизации по сохранённому клубу заявки.
- `D-03` требует единственного перехода из `pending` и одной транзакции для
  решения, данных принявшего Administrator и членства.
- Реализация в
  [applications_http.go](internal/auth/applications_http.go#L542) блокирует
  клуб и заявку, проверяет актуальное полномочие и состояние после получения
  блокировок, затем записывает связанные изменения до одного `COMMIT`.
- Автоматическая проверка находится в
  [applications_integration_test.go](internal/auth/applications_integration_test.go#L251).

## Версия и условия

| Параметр | Значение |
| --- | --- |
| Проверенный commit | `3883bf44c364` |
| Базовый `origin/main` | `59de4ed910ab` |
| Дата проверки | 18 октября 2026 года |
| Go | `go1.26.9 darwin/arm64` |
| PostgreSQL | `15.19` |
| База | отдельная тестовая база из `AUTH_TEST_DATABASE_URL` |
| Изоляция | тест создаёт уникальную схему и удаляет её после выполнения |

Подготовка локальной базы и переменной окружения описана в
[инструкции запуска](PROJECT.md#10-локальный-запуск). Без
`AUTH_TEST_DATABASE_URL` PostgreSQL-сценарий будет пропущен и не является
фактическим подтверждением свойства.

## Исходные данные и фактические результаты

Тест создаёт два активных клуба и реальные серверные сессии четырёх
релевантных субъектов. Заявка пользователя `applicantone` принадлежит клубу A
и до проверок имеет состояние `pending`.

| Субъект и условие | Действие | Ожидаемый результат | Фактический результат |
| --- | --- | --- | --- |
| `applicantone`, автор заявки клуба A | Принять собственную заявку | Отказ без раскрытия и изменения состояния | `404`; текст отсутствует в ответе; остаются `pending`, пустые `administrator_id` и `decided_at`, членств `0` |
| `appadminb`, Administrator только клуба B | Принять заявку клуба A | Такой же безопасный отказ | `404`; текст отсутствует в ответе; состояние заявки и членство не изменились |
| `applicationroot`, SuperUser | Принять заявку клуба A | Глобальная роль не даёт клубного полномочия | `404`; текст отсутствует в ответе; состояние заявки и членство не изменились |
| `appadmina`, действующий Administrator клуба A | Принять заявку клуба A | Успех с серверными данными решения и одним членством | `200`; статус `approved`; записаны ID текущего администратора и время; членств пары пользователь–клуб `1` |
| Заявка уже получила `approved` | Повторно выбрать `rejected` | Первое решение сохраняется | `409`; статус и единственное членство не изменились |
| Два одновременных запроса `approved` и `rejected` | Решить одну `pending`-заявку | Ровно одно решение успешно, второе отклонено | Один `200`, один `409`; финальный статус один; членство присутствует только при `approved` |
| Вставка членства принудительно завершается ошибкой | Выполнить `approved` | Вся попытка откатывается | `500`; заявка остаётся `pending`; членство отсутствует |

Позитивная проверка подтверждает сохранение разрешённой функции. Негативные
проверки подтверждают отказ трём видам неуполномоченных субъектов и сохранение
состояния после отказа. Конкурентная проверка и принудительный сбой подтверждают
наблюдаемые свойства транзакционного решения `D-03`.

## Воспроизведение

```bash
export AUTH_TEST_DATABASE_URL='postgres://club_app:<пароль>@127.0.0.1:5432/club_membership_test?sslmode=disable'

go test -count=1 -v ./internal/auth \
  -run '^TestPostgresApplicationAndMembershipLifecycle$'
```

Сохранённый результат целевого запуска проверенной версии:

```text
=== RUN   TestPostgresApplicationAndMembershipLifecycle
=== RUN   TestPostgresApplicationAndMembershipLifecycle/T-05_to_SR-04_to_D-02_rejects_unauthorized_decisions_without_disclosure_or_state_change
=== RUN   TestPostgresApplicationAndMembershipLifecycle/T-05_to_SR-04_to_D-02_rejects_unauthorized_decisions_without_disclosure_or_state_change/applicant
=== RUN   TestPostgresApplicationAndMembershipLifecycle/T-05_to_SR-04_to_D-02_rejects_unauthorized_decisions_without_disclosure_or_state_change/administrator_of_another_club
=== RUN   TestPostgresApplicationAndMembershipLifecycle/T-05_to_SR-04_to_D-02_rejects_unauthorized_decisions_without_disclosure_or_state_change/SuperUser
observed: all denied decisions returned 404 without application text; status=pending, administrator_id=NULL, decided_at=NULL, memberships=0
=== RUN   TestPostgresApplicationAndMembershipLifecycle/SR-04_to_D-02_allows_the_current_club_administrator_to_approve
observed: current club administrator received 200; status=approved, administrator_id=current actor, decided_at=present, memberships=1
=== RUN   TestPostgresApplicationAndMembershipLifecycle/D-03_preserves_the_first_completed_decision
observed: repeated opposite decision returned 409; approved state and memberships=1 remained unchanged
=== RUN   TestPostgresApplicationAndMembershipLifecycle/D-03_serializes_concurrent_opposite_decisions
observed: concurrent responses=map[200:1 409:1]; final_status=approved; membership matches the final status
=== RUN   TestPostgresApplicationAndMembershipLifecycle/D-03_rolls_back_the_decision_when_membership_creation_fails
observed: forced membership failure returned 500; status=pending, memberships=0
--- PASS: TestPostgresApplicationAndMembershipLifecycle
PASS
ok github.com/tupitsin88/KozyrniyTUZ/internal/auth
```

Дополнительно выполнены:

```text
go test -count=1 ./...  — все пакеты прошли, интеграционные тесты не пропущены
go vet ./...            — exit code 0, диагностик нет
```

## Вывод и границы

На commit `3883bf44c364` подтверждено, что обработчик решения заявки принуждает
`SR-04` для проверенных ролей и клубов, не раскрывает текст при отказе, сохраняет
первое решение при повторе и конкуренции и не оставляет частичное состояние при
подтверждённой ошибке до `COMMIT`.

Проверка относится к пути решения заявки через Go API и настоящую PostgreSQL.
Она не доказывает корректность всех маршрутов приложения, не защищает от
злоупотребления законным полномочием Administrator и не моделирует
неопределённый результат потери соединения во время `COMMIT`. HTTP-запросы
выполняются через in-process handler, поэтому reverse proxy и внешняя сеть в
область свидетельства не входят.
