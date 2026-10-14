/* work-system — демо-туры (П5). Слой поверх страниц: шаги — /tour/data (data/tours/<id>.json),
   якоря — атрибуты data-tour="…" в шаблонах. Конфиг страницы — window.WS_TOUR (templates/_tour.html).

   Шаги: screen — карточка по центру (плитки — сетка); element — подсветка [data-tour=anchor]
   (anchor может быть списком — берётся первый видимый; нет ни одного — шаг пропускается);
   navigate — обычный переход, тур продолжается на новой странице.
   Состояние {tourId, step, startedAt, hist, skipped} — в sessionStorage; если страница не та,
   что ожидает текущий шаг, тур закрывается (пользователь ушёл сам). */
(function () {
    'use strict';
    var cfg = window.WS_TOUR;
    if (!cfg) return;

    var STATE_KEY = 'ws-tour';
    var DATA_KEY = 'ws-tour-data';
    var CLOSED_KEY = 'ws-tour-closed:' + cfg.id;
    var PHONE = window.matchMedia ? window.matchMedia('(max-width: 720px)') : { matches: false };

    function read(key) { try { return JSON.parse(sessionStorage.getItem(key) || 'null'); } catch (e) { return null; } }
    function write(key, value) { try { sessionStorage.setItem(key, JSON.stringify(value)); } catch (e) {} }
    function drop(key) { try { sessionStorage.removeItem(key); } catch (e) {} }
    /* Та же страница: путь и параметры запроса (кроме ?tour=1) совпадают — шаг может вести
       на ту же страницу с фильтром (документы одного сотрудника). */
    function pageKey(url) {
        var u = new URL(url, location.href);
        var params = [];
        u.searchParams.forEach(function (value, key) { if (key !== 'tour') params.push([key, value]); });
        params.sort(function (x, y) { return x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : (x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0); });
        return (u.pathname.replace(/\/+$/, '') || '/') + '?' + JSON.stringify(params);
    }
    function samePath(a, b) { return pageKey(a) === pageKey(b); }

    var tour = null;
    var state = null;
    var root = null;
    var cleanup = [];

    /* ── Данные тура ───────────────────────────────────────────────── */
    function loadTour(done) {
        var cached = read(DATA_KEY);
        if (cached && cached.id === cfg.id && cached.start_url === cfg.start_url) return done(cached);
        fetch('/tour/data', { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .then(function (data) { write(DATA_KEY, data); done(data); })
            .catch(function (e) { console.warn('[tour] не удалось загрузить тур:', e); });
    }

    /* Страница шага — url последнего navigate до него, иначе стартовая. */
    function pageFor(index) {
        for (var i = index; i >= 0; i--) {
            if (tour.steps[i].type === 'navigate') return tour.steps[i].url;
        }
        return tour.start_url;
    }
    function lastShowable() {
        for (var i = tour.steps.length - 1; i >= 0; i--) {
            if (tour.steps[i].type !== 'navigate') return i;
        }
        return -1;
    }
    function totalShown() {
        var n = 0;
        tour.steps.forEach(function (s, i) { if (s.type !== 'navigate' && state.skipped.indexOf(i) < 0) n++; });
        return n;
    }

    /* Липкие/фиксированные панели у верха экрана (шапка, быстрые кнопки кабинета). */
    function isPinned(node) {
        var pos = getComputedStyle(node).position;
        return pos === 'sticky' || pos === 'fixed';
    }
    function inPinned(node) {
        for (var n = node; n && n !== document.body; n = n.parentElement) {
            if (isPinned(n)) return true;
        }
        return false;
    }
    function pinnedBottom() {
        var bottom = 0;
        Array.prototype.forEach.call(document.querySelectorAll('.topbar, .quicknav'), function (n) {
            if (!isPinned(n)) return;
            var r = n.getBoundingClientRect();
            if (r.top <= 1 || r.top < bottom + 1) bottom = Math.max(bottom, r.bottom);
        });
        return bottom;
    }

    function findAnchor(anchor) {
        var names = Array.isArray(anchor) ? anchor : [anchor];
        for (var i = 0; i < names.length; i++) {
            var els = document.querySelectorAll('[data-tour="' + names[i] + '"]');
            for (var j = 0; j < els.length; j++) {
                if (els[j].getClientRects().length) return els[j];
            }
        }
        return null;
    }

    /* ── Ход тура ──────────────────────────────────────────────────── */
    function save() { write(STATE_KEY, state); }

    function go(index) {
        clearStep();
        if (index > lastShowable()) return finish();
        var step = tour.steps[index];
        state.step = index;
        if (step.type === 'navigate') {
            state.step = index + 1;
            save();
            if (samePath(step.url, location.href)) return go(index + 1);
            location.href = step.url;
            return;
        }
        if (!samePath(pageFor(index), location.href)) {
            save();
            location.href = pageFor(index);
            return;
        }
        if (step.type === 'element') {
            var el = findAnchor(step.anchor);
            if (!el) {
                console.warn('[tour] нет якоря data-tour="' + step.anchor + '" — шаг ' + index + ' пропущен');
                if (state.skipped.indexOf(index) < 0) state.skipped.push(index);
                return go(index + 1);
            }
            if (state.hist[state.hist.length - 1] !== index) state.hist.push(index);
            save();
            return showElement(step, el, index);
        }
        if (state.hist[state.hist.length - 1] !== index) state.hist.push(index);
        save();
        showScreen(step, index);
    }

    function back() {
        if (state.hist.length < 2) return;
        state.hist.pop();
        var target = state.hist[state.hist.length - 1];
        state.hist.pop();  // go() положит его обратно
        go(target);
    }

    function close(seen) {
        clearStep();
        drop(STATE_KEY);
        write(CLOSED_KEY, true);
        if (seen) {
            try { fetch('/tour/seen', { method: 'POST', credentials: 'same-origin', keepalive: true }); } catch (e) {}
        }
    }
    function finish() { close(true); }

    /* ── Отрисовка ─────────────────────────────────────────────────── */
    function clearStep() {
        cleanup.forEach(function (fn) { fn(); });
        cleanup = [];
        if (root) { root.remove(); root = null; }
    }

    function el(tag, cls, text) {
        var node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text) node.textContent = text;
        return node;
    }

    function paragraphs(text) {
        var box = el('div', 'tour-body');
        String(text || '').split('\n').forEach(function (line) {
            if (line.trim()) box.appendChild(el('p', '', line));
        });
        return box;
    }

    function buildCard(step, index, extraClass) {
        var card = el('div', 'tour-card' + (extraClass ? ' ' + extraClass : ''));
        card.setAttribute('role', 'dialog');
        card.setAttribute('aria-modal', 'true');
        card.setAttribute('aria-labelledby', 'tour-title');
        card.tabIndex = -1;

        var head = el('div', 'tour-head');
        var title = el('h2', 'tour-title', step.title);
        title.id = 'tour-title';
        head.appendChild(title);
        head.appendChild(el('span', 'tour-count', state.hist.length + ' / ' + totalShown()));
        card.appendChild(head);
        if (step.body) card.appendChild(paragraphs(step.body));
        if (step.tiles && step.tiles.length) {
            var grid = el('div', 'tour-tiles');
            step.tiles.forEach(function (tile) {
                var t = el('div', 'tour-tile');
                t.appendChild(el('b', '', tile.title));
                if (tile.text) t.appendChild(el('span', '', tile.text));
                grid.appendChild(t);
            });
            card.appendChild(grid);
        }

        var isLast = index === lastShowable();
        var foot = el('div', 'tour-foot');
        var left = el('div', 'tour-foot-left');
        var right = el('div', 'tour-foot-right');
        if (!isLast) {
            var skip = el('button', 'tour-btn tour-btn-link', 'Пропустить');
            skip.type = 'button';
            skip.addEventListener('click', function () { close(true); });
            left.appendChild(skip);
        }
        if (state.hist.length > 1) {
            var prev = el('button', 'tour-btn tour-btn-secondary', 'Назад');
            prev.type = 'button';
            prev.addEventListener('click', back);
            right.appendChild(prev);
        }
        var next = el('button', 'tour-btn tour-btn-primary', step.next_label || (isLast ? 'Готово' : 'Далее'));
        next.type = 'button';
        next.setAttribute('data-tour-next', '');
        next.addEventListener('click', function () { isLast ? finish() : go(index + 1); });
        right.appendChild(next);
        foot.appendChild(left);
        foot.appendChild(right);
        card.appendChild(foot);
        return card;
    }

    function mount(card, withDim) {
        root = el('div', 'tour-root');
        root.appendChild(el('div', 'tour-block' + (withDim ? ' tour-dim' : '')));
        root.appendChild(card);
        document.body.appendChild(root);
        var onKey = function (e) {
            if (e.key === 'Escape') { e.preventDefault(); close(true); }
            else if (e.key === 'ArrowRight') { e.preventDefault(); card.querySelector('[data-tour-next]').click(); }
            else if (e.key === 'ArrowLeft') { e.preventDefault(); back(); }
            else if (e.key === 'Tab') {
                var items = card.querySelectorAll('button');
                if (!items.length) return;
                var first = items[0], last = items[items.length - 1];
                if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
                else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
                else if (!card.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
            }
        };
        document.addEventListener('keydown', onKey, true);
        cleanup.push(function () { document.removeEventListener('keydown', onKey, true); });
        var focusTarget = card.querySelector('[data-tour-next]') || card;
        try { focusTarget.focus({ preventScroll: true }); } catch (e) { focusTarget.focus(); }
    }

    function showScreen(step, index) {
        mount(buildCard(step, index, 'tour-screen'), true);
    }

    function showElement(step, target, index) {
        if (step.expand) {
            target.classList.add('is-open');
            cleanup.push(function () { target.classList.remove('is-open'); });
        }
        var box = target.querySelector('[data-tour-box]') || target;
        var pinned = inPinned(box);
        var card = buildCard(step, index, 'tour-tip');
        mount(card, false);
        var hole = el('div', 'tour-hole');
        root.insertBefore(hole, card);

        function place() {
            var r = box.getBoundingClientRect();
            var pad = 6;
            var vw = document.documentElement.clientWidth, vh = window.innerHeight;
            var top = Math.max(r.top - pad, pinned ? 0 : pinnedBottom()), left = Math.max(r.left - pad, 0);
            var bottom = Math.min(r.bottom + pad, vh), right = Math.min(r.right + pad, vw);
            hole.style.top = top + 'px';
            hole.style.left = left + 'px';
            hole.style.width = Math.max(right - left, 0) + 'px';
            hole.style.height = Math.max(bottom - top, 0) + 'px';
            if (PHONE.matches) { card.style.cssText = ''; return; }
            var cw = card.offsetWidth, ch = card.offsetHeight, gap = 14, m = 12;
            var fits = {
                right: right + gap + cw <= vw - m,
                left: left - gap - cw >= m,
                bottom: bottom + gap + ch <= vh - m,
                top: top - gap - ch >= m
            };
            var order = [step.placement || 'bottom', 'bottom', 'top', 'right', 'left'];
            var side = null;
            for (var i = 0; i < order.length; i++) { if (fits[order[i]]) { side = order[i]; break; } }
            var x, y;
            if (side === 'right' || side === 'left') {
                x = side === 'right' ? right + gap : left - gap - cw;
                y = Math.min(Math.max(top, m), vh - ch - m);
            } else if (side) {
                x = Math.min(Math.max(left, m), vw - cw - m);
                y = side === 'bottom' ? bottom + gap : top - gap - ch;
            } else {  // элемент на весь экран — карточка в правом нижнем углу поверх
                x = vw - cw - m * 2;
                y = vh - ch - m * 2;
            }
            card.style.left = Math.max(x, m) + 'px';
            card.style.top = Math.max(y, m) + 'px';
        }

        function scrollTo() {
            if (pinned) return place();  // элемент в липкой шапке/панели виден всегда
            // мгновенно: при scroll-behavior: smooth (кабинет) замер шёл бы посреди анимации
            box.scrollIntoView({ block: 'center', inline: 'nearest', behavior: 'instant' });
            var cover = pinnedBottom();
            var r = box.getBoundingClientRect();
            if (PHONE.matches || r.top < cover + 12) {  // телефон: подсветка сверху; и не под липкой шапкой
                window.scrollBy({ top: r.top - cover - 12, behavior: 'instant' });
            }
            place();
        }

        var frame = 0;
        var onMove = function () { cancelAnimationFrame(frame); frame = requestAnimationFrame(place); };
        window.addEventListener('resize', onMove);
        window.addEventListener('scroll', onMove, true);
        cleanup.push(function () {
            window.removeEventListener('resize', onMove);
            window.removeEventListener('scroll', onMove, true);
            cancelAnimationFrame(frame);
        });
        scrollTo();
        if (step.expand) setTimeout(place, 230);  // полоса раскрывается с анимацией ширины
    }

    /* ── Старт ─────────────────────────────────────────────────────── */
    function begin() {
        state = { tourId: cfg.id, step: 0, startedAt: new Date().toISOString(), hist: [], skipped: [] };
        drop(CLOSED_KEY);
        drop(DATA_KEY);  // новый запуск — свежие шаги с сервера
        save();
    }

    function start() {
        state = read(STATE_KEY);
        if (cfg.force) {
            begin();
            try {  // ?tour=1 убираем из адреса, чтобы перезагрузка не начинала тур заново
                var url = new URL(location.href);
                url.searchParams.delete('tour');
                history.replaceState(null, '', url.pathname + url.search + url.hash);
            } catch (e) {}
        } else if (state && state.tourId === cfg.id) {
            // продолжение тура после перехода
        } else if (cfg.autostart && !read(CLOSED_KEY)) {
            begin();
        } else {
            return;
        }
        loadTour(function (data) {
            tour = data;
            var step = tour.steps[state.step];
            if (!step || !samePath(pageFor(state.step), location.href)) {
                // пользователь ушёл со страницы тура сам — тур закрыт до следующего входа
                drop(STATE_KEY);
                write(CLOSED_KEY, true);
                return;
            }
            go(state.step);
        });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
})();
