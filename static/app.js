const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

let activeJob = null;
let stream = null;
let results = [];
let workingItems = [];
let workingStream = null;
const selectedCountries = new Set();
const excludedCountries = new Set();
const countryCodes = 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK'.split(' ');
const countryNames = new Intl.DisplayNames(['ru'], {type: 'region'});
const countryMap = new Map(countryCodes.map(code => [code, countryNames.of(code) || code]));

async function copySubscription(url) {
    try {
        await navigator.clipboard.writeText(url);
        return true;
    } catch (_) {
        return false;
    }
}

async function prepareDesktopApi() {
    const button = $('#happ-connect-button');
    if (!button || !window.PM_DESKTOP || !window.pywebview?.api) return;
    const status = $('#happ-connect-status');
    try {
        const state = await window.pywebview.api.get_state();
        button.disabled = false;
        if (!state.happInstalled) {
            status.textContent = 'Happ не найден — при нажатии ссылка будет скопирована.';
        }
    } catch (error) {
        status.textContent = `Desktop API недоступен: ${error}`;
        status.className = 'desktop-happ-status error';
    }
}

window.addEventListener('pywebviewready', prepareDesktopApi);

$('#happ-connect-button')?.addEventListener('click', async () => {
    const button = $('#happ-connect-button');
    const status = $('#happ-connect-status');
    button.disabled = true;
    status.textContent = 'Открываю Happ…';
    status.className = 'desktop-happ-status';
    try {
        const result = await window.pywebview.api.open_happ();
        if (result.ok) {
            status.textContent = result.message;
            status.className = 'desktop-happ-status success';
        } else {
            const copied = await copySubscription(result.subscriptionUrl);
            status.textContent = copied ? result.error : `${result.error} Скопируйте ссылку вручную.`;
            status.className = 'desktop-happ-status error';
        }
    } catch (error) {
        status.textContent = `Не удалось вызвать Happ: ${error}`;
        status.className = 'desktop-happ-status error';
    } finally {
        button.disabled = false;
    }
});

function renderCountryOptions() {
    const options = $('#country-options');
    countryCodes
        .sort((a, b) => countryMap.get(a).localeCompare(countryMap.get(b), 'ru'))
        .forEach(code => {
            const option = document.createElement('option');
            option.value = `${countryMap.get(code)} — ${code}`;
            options.append(option);
        });
}

function renderCountryChips(countries, selector, otherCountries) {
    const chips = $(selector);
    chips.replaceChildren();
    [...countries]
        .sort((a, b) => countryMap.get(a).localeCompare(countryMap.get(b), 'ru'))
        .forEach(code => {
            const chip = document.createElement('span');
            chip.className = 'country-chip';
            chip.append(`${countryMap.get(code)} · ${code}`);
            const remove = document.createElement('button');
            remove.type = 'button';
            remove.textContent = '×';
            remove.setAttribute('aria-label', `Убрать ${countryMap.get(code)}`);
            remove.addEventListener('click', () => {
                countries.delete(code);
                renderCountryChips(countries, selector, otherCountries);
            });
            chip.append(remove);
            chips.append(chip);
        });
}

renderCountryOptions();
function bindCountrySearch(inputSelector, countries, chipsSelector, otherCountries, otherChipsSelector) {
    $(inputSelector).addEventListener('change', event => {
    const raw = event.target.value.trim();
    const match = raw.match(/(?:—|\s)([A-Za-z]{2})$/) || raw.match(/^([A-Za-z]{2})$/);
    const code = match ? match[1].toUpperCase() : '';
    if (countryMap.has(code)) {
        otherCountries.delete(code);
        countries.add(code);
        renderCountryChips(countries, chipsSelector, otherCountries);
        renderCountryChips(otherCountries, otherChipsSelector, countries);
        event.target.value = '';
    }
    });
}

bindCountrySearch('#country-search', selectedCountries, '#country-chips', excludedCountries, '#excluded-country-chips');
bindCountrySearch('#excluded-country-search', excludedCountries, '#excluded-country-chips', selectedCountries, '#country-chips');

$('#unlimited-checks').addEventListener('change', event => {
    const input = $('#max-checks');
    input.disabled = event.target.checked;
    input.required = !event.target.checked;
});

function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("pm-theme", theme);
}
setTheme(localStorage.getItem("pm-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
$("#theme-toggle").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));

$$('.nav-item').forEach(button => button.addEventListener('click', () => {
    $$('.nav-item').forEach(item => item.classList.toggle('active', item === button));
    $$('.view').forEach(view => view.classList.toggle('active', view.id === button.dataset.view));
    if (button.dataset.view === 'working-view') loadWorking();
}));

$$('input[name="source"]').forEach(input => input.addEventListener('change', () => {
    $('#custom-source').classList.toggle('hidden', input.value !== 'custom' || !input.checked);
}));

$('#key-file').addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    $('#key-text').value = await file.text();
    $('#file-label').textContent = `${file.name} · ${Math.round(file.size / 1024)} КБ`;
});

function showError(message) {
    $('#form-error').textContent = message;
    $('#form-error').classList.toggle('hidden', !message);
}

function stateLabel(state) {
    const labels = {queued: 'QUEUE', loading: 'LOAD', geolocating: 'GEO', running: 'RUN', measuring: 'SPEED', completed: 'DONE', stopped: 'STOP', failed: 'ERROR'};
    return labels[state] || state.toUpperCase();
}

function updateProgress(data) {
    const found = data.counters?.found ?? data.results?.length ?? results.length;
    const target = data.target || Number($('#count').value);
    $('#found-count').textContent = found;
    $('#target-count').textContent = `из ${target}`;
    $('#checked-count').textContent = data.checked || 0;
    $('#tcp-failed').textContent = data.counters?.tcp_failed || 0;
    $('#tls-failed').textContent = data.counters?.tls_failed || 0;
    $('#xray-failed').textContent = data.counters?.xray_failed || 0;
    $('#geo-matched').textContent = data.counters?.geo_matched || 0;
    const targetProgress = Math.min(found / Math.max(target, 1), 1);
    $('#target-ring').style.setProperty('--progress', `${targetProgress * 360}deg`);
    const scanProgress = data.total ? Math.min((data.checked || 0) / data.total * 100, 100) : 0;
    $('#progress-fill').style.width = `${scanProgress}%`;
    if (data.message) $('#job-message').textContent = data.message;
    if (data.state) setJobState(data.state, data.message);
}

function setJobState(state, message) {
    const badge = $('#job-state');
    badge.className = `state ${state}`;
    badge.textContent = stateLabel(state);
    $('#job-title').textContent = state === 'queued' ? 'Подготовка' : state === 'geolocating' ? 'Фильтр по странам' : state === 'running' ? 'Идёт проверка' : state === 'measuring' ? 'Замер скорости' : state === 'completed' ? 'Проверка завершена' : state === 'failed' ? 'Ошибка' : state === 'stopped' ? 'Остановлено' : 'Загрузка базы';
    if (message) $('#job-message').textContent = message;
    const terminal = ['completed', 'failed', 'stopped'].includes(state);
    $('#stop-button').disabled = terminal;
    $('#start-button').disabled = !terminal;
}

function clearResults() {
    results = [];
    $('#results').className = 'results empty';
    $('#results').replaceChildren();
    const box = document.createElement('div');
    box.className = 'empty-state';
    box.innerHTML = '<span>⌁</span><strong>Идёт поиск</strong><p>Первый рабочий ключ появится сразу после своего каскада.</p>';
    $('#results').append(box);
    $('#download-button').classList.add('disabled');
    $('#subscription-button').disabled = true;
    $('#subscription-box').classList.add('hidden');
}

function resultCard(item, index) {
    const card = document.createElement('article');
    card.className = 'key-card';
    card.dataset.key = item.key;
    const number = document.createElement('span');
    number.className = 'key-index';
    number.textContent = String(index + 1).padStart(2, '0');
    const main = document.createElement('div');
    main.className = 'key-main';
    const name = document.createElement('strong');
    name.textContent = item.name;
    const host = document.createElement('small');
    host.textContent = `${item.host}:${item.port} · ${item.sni || 'без SNI'}`;
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'copy-button';
    copy.textContent = 'КОПИРОВАТЬ';
    copy.addEventListener('click', async () => {
        await navigator.clipboard.writeText(item.key);
        copy.textContent = 'СКОПИРОВАНО';
        setTimeout(() => copy.textContent = 'КОПИРОВАТЬ', 1200);
    });
    main.append(name, host, copy);
    const meta = document.createElement('div');
    meta.className = 'key-meta';
    const values = [`${item.ping ?? '—'} мс`, item.country || 'страна —', item.security, item.network, `score ${item.score}`];
    if (item.speed != null) values.push(`${item.speed} Mbps`);
    values.forEach(value => {
        const badge = document.createElement('span');
        badge.textContent = value;
        meta.append(badge);
    });
    card.append(number, main, meta);
    return card;
}

function addResult(item) {
    if (results.some(existing => existing.key === item.key)) return;
    results.push(item);
    if (results.length === 1) {
        $('#results').replaceChildren();
        $('#results').classList.remove('empty');
        $('#download-button').classList.remove('disabled');
        $('#subscription-button').disabled = false;
    }
    $('#results').append(resultCard(item, results.length - 1));
}

function updateResult(item) {
    const index = results.findIndex(existing => existing.key === item.key);
    if (index === -1) return addResult(item);
    results[index] = item;
    const old = [...$('#results').children][index];
    if (old) old.replaceWith(resultCard(item, index));
}

async function refreshJob() {
    if (!activeJob) return null;
    const response = await fetch(`/api/jobs/${activeJob}`);
    if (!response.ok) return null;
    const data = await response.json();
    updateProgress(data);
    data.results.forEach(updateResult);
    return data;
}

function openStream(jobId) {
    if (stream) stream.close();
    stream = new EventSource(`/api/jobs/${jobId}/events`);
    stream.addEventListener('state', event => {
        const data = JSON.parse(event.data);
        setJobState(data.state, data.message);
        if (['completed', 'failed', 'stopped'].includes(data.state)) {
            refreshJob();
            stream.close();
        }
    });
    stream.addEventListener('loaded', event => {
        const data = JSON.parse(event.data);
        $('#job-message').textContent = `Загружено ключей после фильтров: ${data.total}`;
    });
    stream.addEventListener('key_found', event => {
        addResult(JSON.parse(event.data));
        $('#found-count').textContent = results.length;
        $('#target-ring').style.setProperty('--progress', `${Math.min(results.length / Number($('#count').value), 1) * 360}deg`);
    });
    stream.addEventListener('result_updated', event => updateResult(JSON.parse(event.data)));
    stream.addEventListener('progress', event => updateProgress(JSON.parse(event.data)));
    stream.addEventListener('geo_progress', event => {
        const data = JSON.parse(event.data);
        const stage = data.stage === 'dns' ? 'Определяю IP хостов' : 'Получаю страны IP';
        $('#job-message').textContent = `${stage}: ${data.done} из ${data.total}`;
    });
    stream.addEventListener('geo_complete', event => {
        const data = JSON.parse(event.data);
        $('#geo-matched').textContent = data.matched;
        $('#job-message').textContent = `По странам подошло ${data.matched} из ${data.before}; не определено: ${data.unknown}`;
    });
    // EventSource reconnects by itself; once the job is finished there is nothing
    // left to stream, so close instead of reconnecting in a loop.
    stream.onerror = async () => {
        const job = await refreshJob();
        if (job && ['completed', 'failed', 'stopped'].includes(job.state)) stream.close();
    };
}

$('#job-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    showError('');
    const source = $('input[name="source"]:checked').value;
    const payload = {
        count: Number($('#count').value),
        source,
        text: source === 'custom' ? $('#key-text').value : '',
        workers: 8,
        max_checks: $('#unlimited-checks').checked ? null : Number($('#max-checks').value),
        enable_xray: $('#enable-xray').checked,
        speed: $('#speed').checked,
        filters: {
            security: $('#security').value,
            only_tcp: $('#only-tcp').checked,
            require_sni: $('#require-sni').checked,
            exclude_ws: $('#exclude-ws').checked,
            countries: [...selectedCountries],
            excluded_countries: [...excludedCountries],
        },
    };
    $('#start-button').disabled = true;
    clearResults();
    updateProgress({target: payload.count, checked: 0, counters: {}, state: 'queued', message: 'Создаю задание'});
    try {
        const response = await fetch('/api/jobs', {
            method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось создать задание');
        activeJob = data.id;
        $('#download-button').href = `/api/jobs/${activeJob}/download`;
        $('#stop-button').disabled = false;
        openStream(activeJob);
    } catch (error) {
        showError(error.message);
        setJobState('failed', error.message);
        $('#start-button').disabled = false;
    }
});

$('#stop-button').addEventListener('click', async () => {
    if (!activeJob) return;
    $('#stop-button').disabled = true;
    await fetch(`/api/jobs/${activeJob}/stop`, {method: 'POST'});
});

$('#subscription-button').addEventListener('click', async () => {
    if (!activeJob) return;
    const response = await fetch(`/api/jobs/${activeJob}/subscriptions`, {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name: 'Proxy Manager', ttl_minutes: null}),
    });
    const data = await response.json();
    if (!response.ok) return showError(data.detail || 'Не удалось создать подписку');
    const box = $('#subscription-box');
    box.textContent = data.url;
    box.classList.remove('hidden');
});

function keyWord(count) {
    const mod100 = count % 100;
    const mod10 = count % 10;
    if (mod100 >= 11 && mod100 <= 14) return 'ключей';
    if (mod10 === 1) return 'ключ';
    if (mod10 >= 2 && mod10 <= 4) return 'ключа';
    return 'ключей';
}

async function loadWorking(message = '') {
    const list = $('#working-list');
    const status = $('#working-status');
    list.classList.remove('empty');
    list.textContent = 'Загрузка…';
    const response = await fetch('/api/working?limit=1000&offset=0');
    const page = await response.json();
    const items = Array.isArray(page) ? page : page.items;
    const total = Array.isArray(page) ? items.length : page.total;
    workingItems = items;
    list.replaceChildren();
    $('#working-count').textContent = `${total} ${keyWord(total)}`;
    if (!workingStream) status.textContent = message || (total
        ? `Показаны ${items.length} из ${total} сохранённых ключей.`
        : 'Рабочая база пуста.');
    ['#recheck-working', '#working-happ', '#copy-working'].forEach(selector => {
        $(selector).disabled = !items.length;
    });
    $('#download-working').classList.toggle('disabled', !items.length);
    if (!items.length) {
        list.classList.add('empty');
        list.innerHTML = '<div class="empty-state working-empty"><span class="empty-face">:\'(</span><strong>База пока пуста</strong><p>Успешные проверки сохраняются автоматически.</p></div>';
        return;
    }
    items.forEach((item, index) => {
        const row = document.createElement('article');
        row.className = 'key-card working-row';
        const values = [String(index + 1).padStart(2, '0'), item.name, `${item.ping ?? '—'} мс`, item.country || '—', item.security, `Score ${item.score}`];
        values.forEach((value, valueIndex) => {
            const cell = document.createElement(valueIndex === 1 ? 'strong' : 'span');
            if (valueIndex === 5) cell.className = 'score';
            cell.textContent = value;
            row.append(cell);
        });
        list.append(row);
    });
}
$('#refresh-working').addEventListener('click', loadWorking);

async function workingText() {
    const response = await fetch('/api/working/download');
    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.detail || 'Не удалось получить рабочую базу');
    }
    return response.text();
}

$('#copy-working').addEventListener('click', async () => {
    const button = $('#copy-working');
    const status = $('#working-status');
    try {
        const copied = await copySubscription(await workingText());
        if (!copied) throw new Error('Буфер обмена недоступен');
        button.textContent = 'Скопировано';
        status.textContent = `Скопировано ключей: ${workingItems.length}.`;
        setTimeout(() => button.textContent = 'Скопировать', 1400);
    } catch (error) {
        status.textContent = error.message;
    }
});

$('#working-happ').addEventListener('click', async () => {
    const button = $('#working-happ');
    const status = $('#working-status');
    button.disabled = true;
    status.textContent = 'Создаю локальную подписку…';
    try {
        const response = await fetch('/api/working/subscriptions', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name: 'Рабочая база Proxy Manager', ttl_minutes: null}),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось создать подписку');
        if (window.PM_DESKTOP && window.pywebview?.api) {
            const result = await window.pywebview.api.open_happ(data.url);
            if (!result.ok) {
                const copied = await copySubscription(data.url);
                throw new Error(copied ? result.error : `${result.error} Ссылка: ${data.url}`);
            }
        } else {
            window.location.href = `happ://add/${data.url}`;
        }
        status.textContent = `В Happ передано ключей: ${data.count}. Подтвердите добавление подписки.`;
    } catch (error) {
        status.textContent = error.message;
    } finally {
        button.disabled = !workingItems.length;
    }
});

$('#recheck-working').addEventListener('click', async () => {
    const button = $('#recheck-working');
    const status = $('#working-status');
    const progress = $('#working-progress');
    button.disabled = true;
    status.textContent = 'Запускаю перепроверку рабочей базы…';
    progress.classList.remove('hidden');
    progress.style.setProperty('--progress', '0%');
    try {
        const response = await fetch('/api/working/recheck', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({workers: 8, enable_xray: Boolean(window.PM_XRAY)}),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось запустить перепроверку');
        if (workingStream) workingStream.close();
        workingStream = new EventSource(`/api/jobs/${data.id}/events`);
        workingStream.addEventListener('progress', event => {
            const state = JSON.parse(event.data);
            const percent = state.total ? Math.min(state.checked / state.total, 1) * 100 : 0;
            progress.style.setProperty('--progress', `${percent}%`);
            status.textContent = `Проверено ${state.checked} из ${state.total}; рабочих: ${state.counters.found || 0}.`;
        });
        workingStream.addEventListener('state', event => {
            const state = JSON.parse(event.data);
            status.textContent = state.message;
            if (['completed', 'failed', 'stopped'].includes(state.state)) {
                workingStream.close();
                workingStream = null;
                progress.style.setProperty('--progress', state.state === 'completed' ? '100%' : '0%');
                setTimeout(() => progress.classList.add('hidden'), 900);
                loadWorking(state.message);
            }
        });
        workingStream.onerror = () => {
            status.textContent = 'Соединение с перепроверкой прервано. Обновите список.';
            workingStream?.close();
            workingStream = null;
            button.disabled = !workingItems.length;
        };
    } catch (error) {
        status.textContent = error.message;
        progress.classList.add('hidden');
        button.disabled = !workingItems.length;
    }
});

async function openTelegramProxy(link, button) {
    if (window.PM_DESKTOP && window.pywebview?.api) {
        const result = await window.pywebview.api.open_telegram_proxy(link);
        if (!result.ok) throw new Error(result.error);
    } else {
        window.location.href = link;
    }
    const oldText = button.textContent;
    button.textContent = 'Telegram открыт';
    setTimeout(() => button.textContent = oldText, 1400);
}

function renderTelegramProxies(items) {
    const list = $('#telegram-list');
    list.replaceChildren();
    list.classList.toggle('empty', !items.length);
    if (!items.length) {
        list.innerHTML = '<div class="empty-state telegram-empty"><span class="empty-face">:\'(</span><strong>Рабочих прокси не найдено</strong><p>Попробуйте увеличить количество проверяемых прокси.</p></div>';
        return;
    }
    items.forEach((item, index) => {
        const row = document.createElement('article');
        row.className = 'telegram-row';
        const number = document.createElement('span');
        number.className = 'key-index';
        number.textContent = String(index + 1).padStart(2, '0');
        const endpoint = document.createElement('strong');
        endpoint.textContent = `${item.host}:${item.port}`;
        const ping = document.createElement('span');
        ping.className = 'telegram-ping';
        ping.textContent = `${item.ping} мс`;
        const connect = document.createElement('button');
        connect.type = 'button';
        connect.className = 'secondary-button';
        connect.textContent = 'Открыть в Telegram';
        connect.addEventListener('click', async () => {
            connect.disabled = true;
            try {
                await openTelegramProxy(item.url, connect);
            } catch (error) {
                $('#telegram-status').textContent = error.message;
            } finally {
                connect.disabled = false;
            }
        });
        row.append(number, endpoint, ping, connect);
        list.append(row);
    });
}

$('#telegram-refresh').addEventListener('click', async () => {
    const button = $('#telegram-refresh');
    const status = $('#telegram-status');
    button.disabled = true;
    status.textContent = 'Загружаю источники и проверяю TCP-доступность…';
    try {
        const response = await fetch('/api/telegram/scan', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({limit: Number($('#telegram-limit').value)}),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Не удалось проверить Telegram-прокси');
        renderTelegramProxies(data.working);
        status.textContent = `Собрано ${data.total}, проверено ${data.tested}, доступно ${data.working.length}`;
    } catch (error) {
        status.textContent = error.message;
    } finally {
        button.disabled = false;
    }
});
