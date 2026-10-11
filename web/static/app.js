"use strict";
class ApiError extends Error {
    status;
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}
function requiredElement(id) {
    const target = document.getElementById(id);
    if (!(target instanceof HTMLElement))
        throw new Error("Required page elements are missing");
    return target;
}
const app = requiredElement("app");
const account = requiredElement("account");
const notices = requiredElement("notices");
let csrfToken = "";
let profile = null;
let clubs = [];
let applications = [];
let currentView = "clubs";
let selectedClubID = "";
let authMode = "login";
let noticeTimer = 0;
function element(tag, className = "", text = "") {
    const item = document.createElement(tag);
    if (className)
        item.className = className;
    if (text)
        item.textContent = text;
    return item;
}
async function request(path, method = "GET", data) {
    const headers = new Headers({ Accept: "application/json" });
    const options = { method, headers, credentials: "same-origin" };
    if (data !== undefined) {
        headers.set("Content-Type", "application/json");
        options.body = JSON.stringify(data);
    }
    if (method !== "GET" && csrfToken)
        headers.set("X-CSRF-Token", csrfToken);
    const response = await fetch(path, options);
    if (response.status === 204)
        return undefined;
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
        const errorText = isRecord(payload) && typeof payload.error === "string" ? payload.error : "Не удалось выполнить запрос.";
        throw new ApiError(response.status, userMessage(response.status, errorText));
    }
    return payload;
}
function isRecord(value) {
    return typeof value === "object" && value !== null;
}
function userMessage(status, fallback) {
    if (status === 400)
        return "Проверьте заполненные поля.";
    if (status === 401)
        return "Сессия закончилась. Войдите снова.";
    if (status === 403)
        return "Это действие сейчас недоступно.";
    if (status === 404)
        return "Запись не найдена или доступ к ней закрыт.";
    if (status === 409)
        return "Состояние изменилось. Обновите страницу и попробуйте ещё раз.";
    if (status === 503)
        return "Сервис занят. Попробуйте чуть позже.";
    if (fallback === "transaction outcome unknown")
        return "Сервер проверяет результат операции. Обновите страницу перед повторной попыткой.";
    return "Сейчас не получилось выполнить запрос. Попробуйте ещё раз.";
}
function showNotice(message, isError = false) {
    notices.replaceChildren();
    const notice = element("div", `notice${isError ? " error" : ""}`, message);
    notices.append(notice);
    window.clearTimeout(noticeTimer);
    noticeTimer = window.setTimeout(() => notices.replaceChildren(), 4500);
}
async function loadDashboard() {
    const [newProfile, newClubs, newApplications] = await Promise.all([
        request("/api/profile"),
        request("/api/clubs"),
        request("/api/applications"),
    ]);
    profile = newProfile;
    clubs = newClubs;
    applications = newApplications;
    render();
}
async function start() {
    try {
        const session = await request("/api/session");
        csrfToken = session.csrf_token;
        if (session.authenticated)
            await loadDashboard();
        else
            render();
    }
    catch (error) {
        if (error instanceof ApiError && error.status === 401) {
            profile = null;
            render();
            return;
        }
        profile = null;
        render();
        showNotice(errorText(error), true);
    }
}
function errorText(error) {
    if (error instanceof Error)
        return error.message;
    return "Не удалось выполнить запрос.";
}
function render() {
    account.replaceChildren();
    if (profile) {
        const user = element("span", "account-login", profile.login);
        const role = element("span", "role-label", profile.global_role === "SuperUser" ? "Суперпользователь" : "Участник");
        const logout = element("button", "text-button", "Выйти");
        logout.type = "button";
        logout.addEventListener("click", () => void logOut());
        account.append(user, role, logout);
    }
    if (!profile) {
        renderAuth();
        return;
    }
    app.replaceChildren();
    renderNavigation();
    if (currentView === "clubs")
        renderClubs();
    if (currentView === "applications")
        renderApplications();
    if (currentView === "materials")
        void renderMaterials();
    if (currentView === "manage")
        void renderManagement();
}
function renderAuth() {
    app.replaceChildren();
    const layout = element("section", "auth-layout");
    const intro = element("div", "auth-intro");
    intro.append(element("p", "eyebrow", "Встречайтесь по интересам"));
    intro.append(element("h1", "", "Найдите свой клуб"));
    intro.append(element("p", "", "Общайтесь с единомышленниками, подавайте заявки и читайте материалы клубов, в которых состоите."));
    const panel = element("div", "auth-panel");
    const tabs = element("div", "auth-tabs");
    const loginTab = element("button", "auth-tab", "Вход");
    loginTab.type = "button";
    loginTab.setAttribute("aria-selected", String(authMode === "login"));
    loginTab.addEventListener("click", () => { authMode = "login"; render(); });
    const registerTab = element("button", "auth-tab", "Регистрация");
    registerTab.type = "button";
    registerTab.setAttribute("aria-selected", String(authMode === "register"));
    registerTab.addEventListener("click", () => { authMode = "register"; render(); });
    tabs.append(loginTab, registerTab);
    const form = element("form", "form-grid");
    const login = inputField("Логин", "login", "text", authMode === "register" ? "От 3 до 64 символов" : "Ваш логин");
    login.input.autocomplete = "username";
    login.input.minLength = 3;
    login.input.maxLength = 64;
    login.input.pattern = "[A-Za-z0-9._-]+";
    login.input.required = true;
    const password = inputField("Пароль", "password", "password", authMode === "register" ? "Не короче 12 символов" : "Ваш пароль");
    password.input.autocomplete = authMode === "register" ? "new-password" : "current-password";
    password.input.minLength = authMode === "register" ? 12 : 1;
    password.input.maxLength = 1024;
    password.input.required = true;
    form.append(login.wrapper, password.wrapper);
    const submit = element("button", "button", authMode === "register" ? "Создать аккаунт" : "Войти");
    submit.type = "submit";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        submit.disabled = true;
        try {
            const result = await request(authMode === "register" ? "/api/register" : "/api/login", "POST", {
                login: login.input.value,
                password: password.input.value,
            });
            csrfToken = result.csrf_token;
            currentView = "clubs";
            await loadDashboard();
            showNotice(authMode === "register" ? "Аккаунт создан. Добро пожаловать!" : "Вы вошли.");
        }
        catch (error) {
            showNotice(errorText(error), true);
            submit.disabled = false;
        }
    });
    panel.append(tabs, form);
    layout.append(intro, panel);
    app.append(layout);
}
function inputField(labelText, name, type, hintText = "") {
    const wrapper = element("div", "field");
    const label = element("label", "", labelText);
    label.htmlFor = name;
    const input = element("input");
    input.id = name;
    input.name = name;
    input.type = type;
    wrapper.append(label, input);
    if (hintText)
        wrapper.append(element("span", "hint", hintText));
    return { wrapper, input };
}
function textareaField(labelText, name, hintText = "") {
    const wrapper = element("div", "field");
    const label = element("label", "", labelText);
    label.htmlFor = name;
    const textarea = element("textarea");
    textarea.id = name;
    textarea.name = name;
    textarea.maxLength = 16000;
    wrapper.append(label, textarea);
    if (hintText)
        wrapper.append(element("span", "hint", hintText));
    return { wrapper, textarea };
}
function renderNavigation() {
    const nav = element("nav", "top-nav");
    nav.setAttribute("aria-label", "Основная навигация");
    const tabs = [["clubs", "Клубы"], ["applications", "Мои заявки"]];
    for (const [view, label] of tabs) {
        const button = element("button", "nav-button", label);
        button.type = "button";
        if (currentView === view)
            button.setAttribute("aria-current", "page");
        button.addEventListener("click", () => { currentView = view; render(); });
        nav.append(button);
    }
    app.append(nav);
}
function renderClubs() {
    app.append(element("p", "eyebrow", "Сообщество"));
    app.append(element("h1", "page-heading", "Клубы"));
    app.append(element("p", "lede", "Выберите клуб по интересам. Материалы доступны его участникам."));
    if (profile?.global_role === "User")
        renderCreateClubForm();
    const head = element("div", "section-head");
    head.append(element("h2", "section-title", "Доступные клубы"));
    head.append(element("span", "subtle", `${clubs.length} ${clubs.length === 1 ? "клуб" : "клубов"}`));
    app.append(head);
    if (clubs.length === 0) {
        app.append(emptyState("Здесь пока пусто", "Создайте клуб или загляните сюда позже."));
        return;
    }
    const grid = element("div", "club-grid");
    for (const club of clubs)
        grid.append(renderClubCard(club));
    app.append(grid);
}
function renderCreateClubForm() {
    const details = element("details", "panel");
    const summary = element("summary", "", "Создать клуб");
    summary.className = "section-title";
    details.append(summary);
    const form = element("form", "form-grid");
    const name = inputField("Название", "club-name", "text", "От 1 до 160 символов");
    name.input.maxLength = 160;
    name.input.required = true;
    const description = textareaField("Коротко о клубе", "club-description", "Обычный текст");
    form.append(name.wrapper, description.wrapper);
    const submit = element("button", "button", "Создать клуб");
    submit.type = "submit";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        submit.disabled = true;
        try {
            await request("/api/clubs", "POST", { name: name.input.value, description: description.textarea.value });
            details.open = false;
            await refreshDashboard();
            showNotice("Клуб создан. Вы стали его администратором и участником.");
        }
        catch (error) {
            showNotice(errorText(error), true);
            submit.disabled = false;
        }
    });
    details.append(form);
    app.append(details);
}
function renderClubCard(club) {
    const card = element("article", "club-card");
    const heading = element("h3", "", club.name);
    card.append(heading);
    card.append(element("p", "club-description", club.description || "Описание пока не добавили."));
    const member = profile?.clubs.some((item) => item.id === club.id) ?? false;
    const administrator = profile?.administrator_club_ids.includes(club.id) ?? false;
    const ownPending = applications.some((item) => item.club_id === club.id && item.user_id === profile?.id && item.status === "pending");
    const badges = element("div", "club-meta");
    if (member)
        badges.append(element("span", "badge", "Вы участник"));
    if (administrator)
        badges.append(element("span", "badge", "Администратор"));
    if (ownPending)
        badges.append(element("span", "badge pending", "Заявка на рассмотрении"));
    card.append(badges);
    const actions = element("div", "club-actions");
    if (member) {
        actions.append(actionButton("Материалы", "button", () => { selectedClubID = club.id; currentView = "materials"; render(); }));
    }
    else if (profile?.global_role === "User" && !ownPending) {
        actions.append(actionButton("Подать заявку", "button", () => renderApplicationForm(club)));
    }
    if (administrator) {
        actions.append(actionButton("Управление", "button secondary", () => { selectedClubID = club.id; currentView = "manage"; render(); }));
    }
    if (profile?.global_role === "SuperUser") {
        actions.append(actionButton("Архивировать", "button danger", () => void archive(club)));
    }
    card.append(actions);
    return card;
}
function actionButton(label, className, action) {
    const button = element("button", className, label);
    button.type = "button";
    button.addEventListener("click", action);
    return button;
}
function renderApplicationForm(club) {
    app.replaceChildren();
    renderNavigation();
    app.append(actionLink("← К списку клубов", () => { currentView = "clubs"; render(); }));
    app.append(element("p", "eyebrow", "Заявка в клуб"));
    app.append(element("h1", "page-heading", club.name));
    const panel = element("section", "panel");
    const form = element("form", "form-grid");
    const text = textareaField("Почему хотите присоединиться?", "application-text", "Ваш текст увидят вы и администратор этого клуба.");
    text.textarea.required = true;
    form.append(text.wrapper);
    const submit = element("button", "button", "Отправить заявку");
    submit.type = "submit";
    form.append(submit);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        submit.disabled = true;
        try {
            await request("/api/applications", "POST", { club_id: club.id, text: text.textarea.value });
            currentView = "applications";
            await refreshDashboard();
            showNotice("Заявка отправлена.");
        }
        catch (error) {
            showNotice(errorText(error), true);
            submit.disabled = false;
        }
    });
    panel.append(form);
    app.append(panel);
}
function renderApplications() {
    const own = applications.filter((item) => item.user_id === profile?.id);
    app.append(element("p", "eyebrow", "Ваши обращения"));
    app.append(element("h1", "page-heading", "Мои заявки"));
    app.append(element("p", "lede", "Здесь видны статусы заявок, которые вы отправили в клубы."));
    if (own.length === 0) {
        app.append(emptyState("Заявок пока нет", "Откройте список клубов и отправьте заявку в интересующий вас клуб."));
        return;
    }
    const list = element("div", "stack");
    for (const item of own) {
        const row = element("article", "application-row");
        const club = clubs.find((entry) => entry.id === item.club_id);
        const head = element("div", "row-head");
        head.append(element("h3", "", club?.name ?? "Клуб больше не активен"));
        head.append(statusBadge(item.status));
        row.append(head);
        row.append(element("p", "row-note", formatDate(item.created_at)));
        row.append(element("p", "row-copy", item.text));
        list.append(row);
    }
    app.append(list);
}
function statusBadge(status) {
    const labels = { pending: "На рассмотрении", approved: "Одобрена", rejected: "Отклонена" };
    return element("span", status === "pending" ? "badge pending" : "badge", labels[status]);
}
async function renderMaterials() {
    const club = selectedClub();
    if (!club) {
        currentView = "clubs";
        render();
        return;
    }
    app.append(actionLink("← К списку клубов", () => { currentView = "clubs"; render(); }));
    app.append(element("p", "eyebrow", "Материалы клуба"));
    app.append(element("h1", "page-heading", club.name));
    const loading = emptyState("Загружаем материалы", "");
    app.append(loading);
    try {
        const materials = await request(`/api/clubs/${encodeURIComponent(club.id)}/materials`);
        if (currentView !== "materials" || selectedClubID !== club.id)
            return;
        loading.remove();
        if (materials.length === 0)
            app.append(emptyState("Материалов пока нет", "Администратор клуба сможет добавить их позже."));
        const list = element("div", "stack");
        for (const material of materials)
            list.append(renderMaterialRow(material, false));
        app.append(list);
    }
    catch (error) {
        loading.replaceChildren(element("strong", "", "Не удалось открыть материалы"), element("span", "", errorText(error)));
    }
}
async function renderManagement() {
    const club = selectedClub();
    if (!club || !profile?.administrator_club_ids.includes(club.id)) {
        currentView = "clubs";
        render();
        return;
    }
    app.append(actionLink("← К списку клубов", () => { currentView = "clubs"; render(); }));
    app.append(element("p", "eyebrow", "Управление клубом"));
    app.append(element("h1", "page-heading", club.name));
    const applicationsForClub = applications.filter((item) => item.club_id === club.id);
    const pending = applicationsForClub.filter((item) => item.status === "pending");
    app.append(element("h2", "section-title", `Заявки${pending.length ? ` · ${pending.length} на рассмотрении` : ""}`));
    if (applicationsForClub.length === 0)
        app.append(emptyState("Заявок пока нет", "Новые обращения появятся здесь."));
    const requests = element("div", "stack");
    for (const item of applicationsForClub)
        requests.append(renderAdminApplication(item, club));
    app.append(requests);
    app.append(element("h2", "section-title", "Участники"));
    const memberLoading = emptyState("Загружаем список", "");
    app.append(memberLoading);
    try {
        const members = await request(`/api/clubs/${encodeURIComponent(club.id)}/members`);
        if (currentView !== "manage" || selectedClubID !== club.id)
            return;
        memberLoading.remove();
        renderAddMemberForm(club);
        if (members.length === 0)
            app.append(emptyState("Пока нет участников", ""));
        const memberList = element("div", "stack");
        for (const member of members) {
            const row = element("article", "member-row");
            const identity = element("div");
            identity.append(element("span", "member-login", member.login));
            row.append(identity);
            row.append(actionButton("Убрать", "button small danger", () => void removeMember(club, member)));
            memberList.append(row);
        }
        app.append(memberList);
    }
    catch (error) {
        memberLoading.replaceChildren(element("strong", "", "Не удалось загрузить участников"), element("span", "", errorText(error)));
    }
    void renderManagementMaterials(club);
}
function renderAdminApplication(item, club) {
    const row = element("article", "application-row");
    const head = element("div", "row-head");
    head.append(element("h3", "", item.user_id === profile?.id ? "Ваша заявка" : "Заявка участника"));
    head.append(statusBadge(item.status));
    row.append(head);
    row.append(element("p", "row-note", `Отправлена ${formatDate(item.created_at)}`));
    row.append(element("p", "row-copy", item.text));
    if (item.status === "pending") {
        const actions = element("div", "row-actions");
        actions.append(actionButton("Одобрить", "button small", () => void decide(item, "approved")));
        actions.append(actionButton("Отклонить", "button small secondary", () => void decide(item, "rejected")));
        row.append(actions);
    }
    return row;
}
function renderAddMemberForm(club) {
    const form = element("form", "panel form-grid");
    const login = inputField("Добавить по логину", `member-login-${club.id}`, "text", "Например, maria.pet");
    login.input.autocomplete = "off";
    login.input.maxLength = 64;
    login.input.required = true;
    const submit = element("button", "button", "Добавить участника");
    submit.type = "submit";
    form.append(login.wrapper, submit);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        submit.disabled = true;
        try {
            await request(`/api/clubs/${encodeURIComponent(club.id)}/members`, "POST", { login: login.input.value });
            await refreshDashboard();
            showNotice("Участник добавлен.");
        }
        catch (error) {
            showNotice(errorText(error), true);
            submit.disabled = false;
        }
    });
    app.append(form);
}
function renderMaterialRow(material, editable) {
    const row = element("article", "material-row");
    const head = element("div", "row-head");
    head.append(element("h3", "", "Материал"));
    head.append(element("span", "row-note", `Обновлён ${formatDate(material.updated_at)}`));
    row.append(head);
    if (!editable) {
        row.append(element("p", "row-copy", material.content));
        return row;
    }
    const form = element("form", "form-grid");
    const content = element("textarea", "material-editor");
    content.value = material.content;
    content.maxLength = 16000;
    content.setAttribute("aria-label", "Содержимое материала");
    form.append(content);
    const save = element("button", "button small", "Сохранить изменения");
    save.type = "submit";
    form.append(save);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        save.disabled = true;
        try {
            await request(`/api/materials/${encodeURIComponent(material.id)}`, "PUT", { content: content.value });
            await refreshDashboard();
            showNotice("Материал обновлён.");
        }
        catch (error) {
            showNotice(errorText(error), true);
            save.disabled = false;
        }
    });
    row.append(form);
    return row;
}
function renderCreateMaterialForm(club) {
    const details = element("details", "panel");
    const summary = element("summary", "section-title", "Добавить материал");
    details.append(summary);
    const form = element("form", "form-grid");
    const content = textareaField("Текст материала", `new-material-${club.id}`, "Обычный текст, без HTML и разметки.");
    content.textarea.required = true;
    const submit = element("button", "button", "Опубликовать");
    submit.type = "submit";
    form.append(content.wrapper, submit);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        submit.disabled = true;
        try {
            await request(`/api/clubs/${encodeURIComponent(club.id)}/materials`, "POST", { content: content.textarea.value });
            await refreshDashboard();
            showNotice("Материал опубликован.");
        }
        catch (error) {
            showNotice(errorText(error), true);
            submit.disabled = false;
        }
    });
    details.append(form);
    app.append(details);
}
async function renderManagementMaterials(club) {
    const section = element("section");
    section.append(element("h2", "section-title", "Материалы"));
    const loading = emptyState("Загружаем материалы", "");
    section.append(loading);
    app.append(section);
    try {
        const materials = await request(`/api/clubs/${encodeURIComponent(club.id)}/materials`);
        if (currentView !== "manage" || selectedClubID !== club.id)
            return;
        loading.remove();
        renderCreateMaterialForm(club);
        if (materials.length === 0)
            section.append(emptyState("Материалов пока нет", "Добавьте первый материал клуба."));
        const list = element("div", "stack");
        for (const material of materials)
            list.append(renderMaterialRow(material, true));
        section.append(list);
    }
    catch (error) {
        loading.replaceChildren(element("strong", "", "Не удалось загрузить материалы"), element("span", "", errorText(error)));
    }
}
function actionLink(label, action) {
    const link = element("a", "back-link", label);
    link.href = "/";
    link.addEventListener("click", (event) => { event.preventDefault(); action(); });
    return link;
}
function emptyState(title, detail) {
    const state = element("div", "empty-state");
    state.append(element("strong", "", title));
    if (detail)
        state.append(element("span", "", detail));
    return state;
}
function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.valueOf()))
        return "";
    return new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium" }).format(date);
}
function selectedClub() {
    return clubs.find((club) => club.id === selectedClubID);
}
async function refreshDashboard() {
    await loadDashboard();
}
async function decide(item, status) {
    try {
        await request(`/api/applications/${encodeURIComponent(item.id)}/decision`, "POST", { status });
        await refreshDashboard();
        showNotice(status === "approved" ? "Заявка одобрена, пользователь добавлен в клуб." : "Заявка отклонена.");
    }
    catch (error) {
        showNotice(errorText(error), true);
    }
}
async function removeMember(club, member) {
    if (!window.confirm(`Убрать ${member.login} из клуба «${club.name}»?`))
        return;
    try {
        await request(`/api/clubs/${encodeURIComponent(club.id)}/members/${encodeURIComponent(member.user_id)}`, "DELETE");
        await refreshDashboard();
        showNotice("Участник удалён из клуба.");
    }
    catch (error) {
        showNotice(errorText(error), true);
    }
}
async function archive(club) {
    if (!window.confirm(`Архивировать клуб «${club.name}»? Участники потеряют доступ к его материалам.`))
        return;
    try {
        await request(`/api/clubs/${encodeURIComponent(club.id)}`, "DELETE");
        await refreshDashboard();
        showNotice("Клуб архивирован.");
    }
    catch (error) {
        showNotice(errorText(error), true);
    }
}
async function logOut() {
    try {
        await request("/api/logout", "POST", {});
    }
    catch (error) {
        if (!(error instanceof ApiError && error.status === 401)) {
            showNotice(errorText(error), true);
            return;
        }
    }
    csrfToken = "";
    profile = null;
    clubs = [];
    applications = [];
    currentView = "clubs";
    render();
}
void start();
