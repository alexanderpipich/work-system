/* work-system — общие микровзаимодействия. Подключается из base.html. */
(function () {
    'use strict';
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    /* ── 001. Логотип вращается 2 с — один раз за сессию ─────────────── */
    function initLogoSpin() {
        var logos = document.querySelectorAll('.brand img, .auth-logo img');
        if (!logos.length || reduce) return;
        var KEY = 'ws-logo-spun';
        function spin(el) {
            try { if (sessionStorage.getItem(KEY)) return; } catch (e) {}
            try { sessionStorage.setItem(KEY, '1'); } catch (e) {}
            el.classList.add('is-spinning');
            setTimeout(function () { el.classList.remove('is-spinning'); }, 2000);
        }
        Array.prototype.forEach.call(logos, function (el) {
            el.addEventListener('mouseenter', function () { spin(el); });
            el.addEventListener('click', function () { spin(el); });
        });
    }

    /* ── 004. Рябь: каждые 120 с, 3 круга, случайная точка ───────────── */
    function initRipple() {
        if (reduce) return;
        var layer = document.createElement('div');
        layer.className = 'ripple-layer';
        layer.setAttribute('aria-hidden', 'true');
        document.body.appendChild(layer);

        function drop() {
            if (document.hidden) return;
            var x = 8 + Math.random() * 84;
            var y = 8 + Math.random() * 84;
            for (var i = 0; i < 3; i++) {
                (function (i) {
                    var r = document.createElement('span');
                    r.className = 'ripple';
                    r.style.left = x + '%';
                    r.style.top = y + '%';
                    r.style.animationDelay = (i * 0.38) + 's';
                    r.style.opacity = String(1 - i * 0.28);
                    layer.appendChild(r);
                    setTimeout(function () { r.remove(); }, 3600 + i * 400);
                })(i);
            }
        }
        setInterval(drop, 120000);

        /* демо-режим (только страница превью дизайн-системы) */
        if (document.documentElement.hasAttribute('data-ripple-demo')) {
            setTimeout(drop, 2500);
            setInterval(drop, 9000);
        }
    }

    /* ── Тоггл строк «смена без плана» (табель и графики) ────────────── */
    /* Только отображение: строки прячутся классом, суммы и расчёт не трогаются.
       Кнопка живёт на двух страницах, поэтому логика здесь, а не в шаблонах. */
    function initRowToggle() {
        var buttons = document.querySelectorAll('[data-toggle-rows]');
        Array.prototype.forEach.call(buttons, function (btn) {
            var table = document.querySelector(btn.getAttribute('data-toggle-rows'));
            if (!table) { return; }

            var hidden = table.querySelectorAll('tr[data-no-plan]').length;
            if (!hidden) {
                /* Прятать нечего — кнопка молча исчезает, чтобы не обманывать. */
                btn.hidden = true;
                return;
            }

            var labelHide = btn.getAttribute('data-label-hide') || btn.textContent;
            var labelShow = btn.getAttribute('data-label-show') || labelHide;

            btn.addEventListener('click', function () {
                var isHiding = !table.classList.contains('rows-hidden');
                table.classList.toggle('rows-hidden', isHiding);
                btn.setAttribute('aria-pressed', isHiding ? 'true' : 'false');
                /* Счётчик в подписи: иначе непонятно, сколько строк ушло и
                   почему суммы под таблицей больше не сходятся с видимым. */
                btn.textContent = isHiding
                    ? labelShow + ' (скрыто: ' + hidden + ')'
                    : labelHide;
            });
        });
    }

    /* ── Попап смены без плана (табель и графики, до фиксации) ───────── */
    function initNoPlanPopup() {
        var popup = document.getElementById('no-plan-popup');
        if (!popup) { return; }

        function close() { popup.classList.remove('open'); }

        function fill(id, value) {
            var node = document.getElementById(id);
            if (node) { node.textContent = value || '—'; }
        }

        /* Делегирование: ячеек в табеле сотни, вешать обработчик на каждую
           незачем, да и таблица может перерисовываться. */
        document.addEventListener('click', function (e) {
            var cell = e.target.closest ? e.target.closest('[data-np-cell]') : null;
            if (!cell) { return; }
            e.preventDefault();

            var store = cell.getAttribute('data-np-store') || '';
            fill('np-employee', cell.getAttribute('data-np-employee'));
            fill('np-store', store);
            fill('np-date', cell.getAttribute('data-np-date'));
            fill('np-hours', cell.getAttribute('data-np-hours'));

            var mail = document.getElementById('np-mail');
            if (mail) {
                /* Роут сам вытащит номер ТК из названия магазина. */
                mail.href = '/admin/email/unplanned?store=' + encodeURIComponent(store);
            }
            popup.classList.add('open');
        });

        popup.addEventListener('click', function (e) {
            /* Клик по подложке или по кнопкам «Отмена»/«×». */
            if (e.target === popup || (e.target.closest && e.target.closest('[data-np-close]'))) {
                close();
            }
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') { close(); }
        });
    }

    /* ── Недоступный раздел (П2): карточка с data-locked ─────────────────
       Клик (и Enter — браузер превращает его в click на ссылке) не уводит на
       страницу, а объясняет, каким ролям раздел открыт. Текст берётся из
       data-message, иначе собирается из data-title и data-roles. */
    function initLockedNav() {
        var modal = document.getElementById('nav-lock-modal');
        if (!modal) { return; }
        var kicker = document.getElementById('nav-lock-kicker');
        var title = document.getElementById('nav-lock-title');
        var text = document.getElementById('nav-lock-text');

        function close() { modal.classList.remove('open'); }

        function open(card) {
            var name = card.getAttribute('data-title') || '';
            var soon = card.hasAttribute('data-coming-soon');
            var message = card.getAttribute('data-message');
            if (!message) {
                message = soon
                    ? 'Модуль «' + name + '» в разработке.'
                    : 'Раздел «' + name + '» доступен ролям: ' + (card.getAttribute('data-roles') || '—') + '.';
            }
            kicker.textContent = soon ? 'Скоро' : 'Нет доступа';
            title.textContent = soon ? 'Модуль в разработке' : name;
            text.textContent = message;
            modal.classList.add('open');
            var ok = modal.querySelector('.m-btn');
            if (ok) { ok.focus(); }
        }

        document.addEventListener('click', function (e) {
            var card = e.target.closest ? e.target.closest('[data-locked]') : null;
            if (!card) { return; }
            e.preventDefault();
            open(card);
        });

        modal.addEventListener('click', function (e) {
            if (e.target === modal || (e.target.closest && e.target.closest('[data-nav-lock-close]'))) {
                close();
            }
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') { close(); }
        });
    }

    /* ── Просмотр документа во всплывающем окне (П4) ──────────────────────
       Ссылка с data-preview-url: PDF — iframe, изображение — img, прочее
       (HEIC) — только «Скачать». Делегирование: ссылок в реестре сотни. */
    function initDocPreview() {
        var modal = document.getElementById('doc-preview-modal');
        if (!modal) { return; }
        var body = document.getElementById('doc-preview-body');
        var title = document.getElementById('doc-preview-title');
        var download = document.getElementById('doc-preview-download');

        function close() {
            modal.classList.remove('open');
            body.innerHTML = '';  /* выгрузить iframe — иначе PDF продолжает висеть в памяти */
        }

        function open(link) {
            var kind = link.getAttribute('data-preview-kind');
            var url = link.getAttribute('data-preview-url');
            body.innerHTML = '';
            var node;
            if (kind === 'pdf') {
                node = document.createElement('iframe');
                node.src = url;
                node.title = link.getAttribute('data-preview-title') || 'Документ';
            } else if (kind === 'image') {
                node = document.createElement('img');
                node.src = url;
                node.alt = link.getAttribute('data-preview-title') || 'Документ';
            } else {
                node = document.createElement('p');
                node.className = 'preview-none';
                node.textContent = 'Браузер не показывает этот формат — скачайте файл.';
            }
            body.appendChild(node);
            title.textContent = link.getAttribute('data-preview-title') || 'Документ';
            download.href = link.getAttribute('data-download-url') || url;
            modal.classList.add('open');
        }

        document.addEventListener('click', function (e) {
            var link = e.target.closest ? e.target.closest('[data-preview-url]') : null;
            if (!link) { return; }
            e.preventDefault();
            open(link);
        });

        modal.addEventListener('click', function (e) {
            if (e.target === modal || (e.target.closest && e.target.closest('[data-preview-close]'))) {
                close();
            }
        });

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && modal.classList.contains('open')) { close(); }
        });
    }

    /* ── Массовый выбор строк (П4, «Проверено (N)») ────────────────────────
       data-bulk-all / -item / -count / -submit с одним именем группы. */
    function initBulkSelect() {
        function items(group) {
            return document.querySelectorAll('[data-bulk-item="' + group + '"]');
        }
        function refresh(group) {
            var checked = 0;
            items(group).forEach(function (box) { if (box.checked) { checked += 1; } });
            document.querySelectorAll('[data-bulk-count="' + group + '"]').forEach(function (node) {
                node.textContent = checked;
            });
            document.querySelectorAll('[data-bulk-submit="' + group + '"]').forEach(function (btn) {
                btn.disabled = checked === 0;
            });
        }
        document.addEventListener('change', function (e) {
            var target = e.target;
            if (!target.getAttribute) { return; }
            var all = target.getAttribute('data-bulk-all');
            if (all) {
                items(all).forEach(function (box) { box.checked = target.checked; });
                refresh(all);
                return;
            }
            var group = target.getAttribute('data-bulk-item');
            if (group) { refresh(group); }
        });
    }

    function init() { initLogoSpin(); initRipple(); initRowToggle(); initNoPlanPopup(); initLockedNav(); initDocPreview(); initBulkSelect(); }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
