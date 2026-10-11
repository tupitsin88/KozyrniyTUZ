import { expect, test } from "@playwright/test";

async function register(page, login) {
  await page.goto("/");
  await page.getByRole("button", { name: "Регистрация" }).click();
  await page.getByLabel("Логин").fill(login);
  await page.getByLabel("Пароль").fill("e2e-correct-horse-battery");
  await page.getByRole("button", { name: "Создать аккаунт" }).click();
  await expect(page.getByRole("heading", { name: "Клубы" })).toBeVisible();
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
  await expect(clubCard.getByText("Заявка на рассмотрении")).toBeVisible();
  await expect(clubCard.getByRole("button", { name: "Подать заявку" })).toHaveCount(0);

  await page.reload();
  await page.locator(".club-card").filter({ hasText: clubName }).getByRole("button", { name: "Управление" }).click();
  await page.getByRole("button", { name: "Одобрить" }).click();
  await expect(page.getByText("Заявка одобрена, пользователь добавлен в клуб.")).toBeVisible();

  await page.locator("summary").filter({ hasText: "Добавить материал" }).click();
  await page.getByLabel("Текст материала").fill(xssPayload);
  await page.getByRole("button", { name: "Опубликовать" }).click();
  await expect(page.getByText("Материал опубликован.")).toBeVisible();

  await applicant.reload();
  await applicant.locator(".club-card").filter({ hasText: clubName }).getByRole("button", { name: "Материалы" }).click();
  await expect(applicant.locator(".material-row .row-copy")).toHaveText(xssPayload);
  await expect(applicant.locator(".material-row img")).toHaveCount(0);
  expect(await applicant.evaluate(() => window.__e2eXSS ?? 0)).toBe(0);
  await applicantContext.close();
});
