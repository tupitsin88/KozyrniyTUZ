import { expect, test } from "@playwright/test";

async function register(page, login) {
  await page.goto("/");
  await page.getByRole("button", { name: "Регистрация" }).click();
  await page.getByLabel("Логин").fill(login);
  await page.getByLabel("Пароль").fill("e2e-correct-horse-battery");
  await page.getByRole("button", { name: "Создать аккаунт" }).click();
  await expect(page.getByRole("heading", { name: "Клубы", exact: true })).toBeVisible();
}

async function signIn(page, login, password) {
  await page.goto("/");
  await page.getByLabel("Логин").fill(login);
  await page.getByLabel("Пароль").fill(password);
  await page.getByRole("button", { name: "Войти" }).click();
  await expect(page.getByRole("heading", { name: "Клубы", exact: true })).toBeVisible();
}

async function activeClubID(page, name) {
  return page.evaluate(async (clubName) => {
    let cursor = null;
    do {
      const url = new URL("/api/clubs", window.location.origin);
      url.searchParams.set("limit", "100");
      if (cursor) url.searchParams.set("cursor", cursor);
      const response = await fetch(url);
      if (!response.ok) throw new Error(`club list failed with ${response.status}`);
      const clubs = await response.json();
      const match = clubs.find((club) => club.name === clubName);
      if (match) return match.id;
      cursor = response.headers.get("X-Next-Cursor");
    } while (cursor);
    throw new Error(`active club not found: ${clubName}`);
  }, name);
}

test("registration, club request, materials, pagination and safe text rendering", async ({ browser, page }) => {
  const suffix = `${Date.now()}${Math.floor(Math.random() * 1000)}`;
  const clubName = `E2E Club ${suffix}`;
  const secondClubName = `E2E Club Two ${suffix}`;
  const applicantLogin = `e2euser${suffix}`;
  const xssPayload = '<img src=x onerror="window.__e2eXSS=1">';

  await register(page, `e2eowner${suffix}`);
  await page.locator("summary").filter({ hasText: "Создать клуб" }).click();
  await page.getByLabel("Название").fill(clubName);
  await page.getByLabel("Коротко о клубе").fill("Клуб для браузерной проверки.");
  await page.locator("form").getByRole("button", { name: "Создать клуб" }).click();
  await expect(page.locator(".club-card").filter({ hasText: clubName })).toBeVisible();
  const clubID = await activeClubID(page, clubName);

  await page.locator("summary").filter({ hasText: "Создать клуб" }).click();
  await page.getByLabel("Название").fill(secondClubName);
  await page.getByLabel("Коротко о клубе").fill("Вторая запись для проверки курсора.");
  await page.locator("form").getByRole("button", { name: "Создать клуб" }).click();
  await expect(page.locator(".club-card").filter({ hasText: secondClubName })).toBeVisible();

  const cursorPage = await page.evaluate(async () => {
    const firstResponse = await fetch("/api/clubs?limit=1");
    const firstItems = await firstResponse.json();
    const nextCursor = firstResponse.headers.get("X-Next-Cursor");
    if (!nextCursor) throw new Error("expected another club page");
    const nextResponse = await fetch(`/api/clubs?limit=1&cursor=${encodeURIComponent(nextCursor)}`);
    return { firstItems, nextItems: await nextResponse.json() };
  });
  expect(cursorPage.firstItems).toHaveLength(1);
  expect(cursorPage.nextItems).toHaveLength(1);
  expect(cursorPage.nextItems[0].id).not.toBe(cursorPage.firstItems[0].id);

  const profilePage = await page.evaluate(async () => {
    const firstResponse = await fetch("/api/profile?limit=1");
    const first = await firstResponse.json();
    const nextCursor = firstResponse.headers.get("X-Next-Cursor");
    if (!nextCursor) throw new Error("expected another profile page");
    const nextResponse = await fetch(`/api/profile?limit=1&cursor=${encodeURIComponent(nextCursor)}`);
    const next = await nextResponse.json();
    return { first, next };
  });
  const firstProfileClub = profilePage.first.clubs[0]?.id ?? profilePage.first.administrator_club_ids[0];
  const nextProfileClub = profilePage.next.clubs[0]?.id ?? profilePage.next.administrator_club_ids[0];
  expect(firstProfileClub).toBeTruthy();
  expect(nextProfileClub).toBeTruthy();
  expect(nextProfileClub).not.toBe(firstProfileClub);

  const applicantContext = await browser.newContext();
  const applicant = await applicantContext.newPage();
  await register(applicant, applicantLogin);
  const clubCard = applicant.locator(".club-card").filter({ hasText: clubName });
  await clubCard.getByRole("button", { name: "Подать заявку" }).click();
  await applicant.getByLabel("Почему хотите присоединиться?").fill("Хочу участвовать.");
  await applicant.getByRole("button", { name: "Отправить заявку" }).click();
  await expect(applicant.getByText("Заявка отправлена.")).toBeVisible();
  await expect(applicant.getByText("На рассмотрении", { exact: true })).toBeVisible();
  await applicant.getByRole("button", { name: "Клубы", exact: true }).click();
  await expect(clubCard.getByText("Заявка на рассмотрении")).toBeVisible();
  await expect(clubCard.getByRole("button", { name: "Подать заявку" })).toHaveCount(0);

  const outsiderContext = await browser.newContext();
  const outsider = await outsiderContext.newPage();
  await register(outsider, `e2eoutsider${suffix}`);
  const deniedArchive = await outsider.evaluate(async (id) => {
    const sessionResponse = await fetch("/api/session");
    const session = await sessionResponse.json();
    const response = await fetch(`/api/clubs/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { "X-CSRF-Token": session.csrf_token },
    });
    return response.status;
  }, clubID);
  expect(deniedArchive).toBe(403);

  await page.reload();
  await page.locator(".club-card").filter({ hasText: clubName }).getByRole("button", { name: "Управление" }).click();
  await page.getByRole("button", { name: "Одобрить" }).click();
  await expect(page.getByText("Заявка одобрена, пользователь добавлен в клуб.")).toBeVisible();

  await page.locator("summary").filter({ hasText: "Добавить материал" }).click();
  await page.getByLabel("Текст материала").fill(xssPayload);
  await page.getByRole("button", { name: "Опубликовать" }).click();
  await expect(page.getByText("Материал опубликован.")).toBeVisible();
  const materialID = await page.evaluate(async (id) => {
    const response = await fetch(`/api/clubs/${encodeURIComponent(id)}/materials?limit=1`);
    if (!response.ok) throw new Error(`material list failed with ${response.status}`);
    const materials = await response.json();
    if (!materials[0]) throw new Error("material was not persisted");
    return materials[0].id;
  }, clubID);
  const deniedMaterialRead = await outsider.evaluate(async (id) => {
    const response = await fetch(`/api/materials/${encodeURIComponent(id)}`);
    return response.status;
  }, materialID);
  expect(deniedMaterialRead).toBe(404);

  await applicant.reload();
  await applicant.locator(".club-card").filter({ hasText: clubName }).getByRole("button", { name: "Материалы" }).click();
  await expect(applicant.locator(".material-row .row-copy")).toHaveText(xssPayload);
  await expect(applicant.locator(".material-row img")).toHaveCount(0);
  expect(await applicant.evaluate(() => window.__e2eXSS ?? 0)).toBe(0);

  page.on("dialog", (dialog) => dialog.accept());
  await page.locator(".member-row").filter({ hasText: applicantLogin }).getByRole("button", { name: "Убрать" }).click();
  await expect(page.locator(".member-row").filter({ hasText: applicantLogin })).toHaveCount(0);
  await applicant.reload();
  await expect(applicant.locator(".club-card").filter({ hasText: clubName }).getByRole("button", { name: "Материалы" })).toHaveCount(0);
  const deniedAfterRemoval = await applicant.evaluate(async (id) => {
    const response = await fetch(`/api/materials/${encodeURIComponent(id)}`);
    return response.status;
  }, materialID);
  expect(deniedAfterRemoval).toBe(404);

  const superUserContext = await browser.newContext();
  const superUser = await superUserContext.newPage();
  await signIn(
    superUser,
    process.env.BOOTSTRAP_SUPERUSER_LOGIN ?? "e2e-root",
    process.env.BOOTSTRAP_SUPERUSER_PASSWORD ?? "e2e-bootstrap-password-long-enough",
  );
  superUser.on("dialog", (dialog) => dialog.accept());
  await superUser.locator(".club-card").filter({ hasText: clubName }).getByRole("button", { name: "Архивировать" }).click();
  await expect(superUser.locator(".club-card").filter({ hasText: clubName })).toHaveCount(0);
  const deniedAfterArchive = await page.evaluate(async (id) => {
    const response = await fetch(`/api/materials/${encodeURIComponent(id)}`);
    return response.status;
  }, materialID);
  expect(deniedAfterArchive).toBe(404);

  await superUserContext.close();
  await outsiderContext.close();
  await applicantContext.close();
});
