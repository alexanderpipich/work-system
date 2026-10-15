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

    /* ── Боковая полоса рабочего стола (П4.9) ──────────────────────────────
       Клик по группе — плавная прокрутка к её секции; при прокрутке активная
       группа подсвечивается (IntersectionObserver). Подразделы — обычные ссылки. */
    // Секция рабочего стола — цель прокрутки из полосы. Вне дашборда элемент с тем же id
    // может оказаться чем угодно, поэтому считаем только группы карточек дашборда.
    function dashSection(id) {
        var el = id ? document.getElementById(id) : null;
        return el && el.closest && el.closest('.dash') ? el : null;
    }

    function initRail() {
        var rail = document.querySelector('.rail');
        if (!rail) { return; }
        var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        var behavior = reduced ? 'auto' : 'smooth';
        var groups = {};
        var lastOutside = null;

        rail.addEventListener('click', function (e) {
            var top = e.target.closest ? e.target.closest('[data-rail-top]') : null;
            if (top) {
                e.preventDefault();
                window.scrollTo({ top: 0, behavior: behavior });
                return;
            }
            var link = e.target.closest ? e.target.closest('[data-rail-anchor]') : null;
            if (!link) { return; }
            var id = link.getAttribute('data-rail-anchor');
            var section = dashSection(id);
            // Вне дашборда ссылка ведёт на свой дашборд к якорю (/hr#payouts) — обычный переход.
            if (!section) { return; }
            e.preventDefault();
            section.scrollIntoView({ behavior: behavior, block: 'start' });
            if (window.history && history.replaceState) { history.replaceState(null, '', '#' + id); }
        });

        // Клавиатура (П4.10): Tab в полосу раскрывает её (:focus-within), Esc сворачивает
        // и возвращает фокус туда, где он был до входа в полосу.
        document.addEventListener('focusin', function (e) {
            if (!rail.contains(e.target)) { lastOutside = e.target; }
            else { rail.classList.remove('is-collapsed'); }
        });
        rail.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape' && e.key !== 'Esc') { return; }
            rail.classList.add('is-collapsed');
            if (lastOutside && document.contains(lastOutside) && lastOutside.focus) {
                lastOutside.focus();
            } else if (document.activeElement && document.activeElement.blur) {
                document.activeElement.blur();
            }
        });
        rail.addEventListener('mouseleave', function () { rail.classList.remove('is-collapsed'); });

        var items = rail.querySelectorAll('[data-rail-group]');
        for (var i = 0; i < items.length; i++) {
            groups[items[i].getAttribute('data-rail-group')] = items[i];
        }
        if (!('IntersectionObserver' in window)) { return; }

        var sections = [];
        var visible = {};
        Object.keys(groups).forEach(function (id) {
            var section = dashSection(id);
            if (section) { sections.push(section); }
        });
        // Вне дашборда секций нет — подсветку ставит сервер по текущему пути.
        if (!sections.length) { return; }

        function mark() {
            var active = null;
            for (var j = 0; j < sections.length; j++) {
                if (visible[sections[j].id]) { active = sections[j].id; break; }
            }
            if (!active) { return; }
            Object.keys(groups).forEach(function (id) {
                groups[id].classList.toggle('is-active', id === active);
            });
        }

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) { visible[entry.target.id] = entry.isIntersecting; });
            mark();
        }, { rootMargin: '-15% 0px -60% 0px' });
        sections.forEach(function (section) { observer.observe(section); });
    }

    // Выдвижное меню на телефоне (П4.10): кнопка в шапке, закрытие крестиком, по фону и Esc;
    // фокус уходит в панель и возвращается на кнопку.
    function initDrawer() {
        var drawer = document.getElementById('nav-drawer');
        var button = document.querySelector('[data-drawer-open]');
        if (!drawer || !button) { return; }
        var panel = drawer.querySelector('.drawer-panel');

        function open() {
            drawer.hidden = false;
            button.setAttribute('aria-expanded', 'true');
            document.documentElement.classList.add('drawer-open');
            var current = panel.querySelector('[aria-current="page"]');
            (current || panel).focus();
        }
        function close() {
            if (drawer.hidden) { return; }
            drawer.hidden = true;
            button.setAttribute('aria-expanded', 'false');
            document.documentElement.classList.remove('drawer-open');
            button.focus();
        }

        button.addEventListener('click', open);
        drawer.addEventListener('click', function (e) {
            if (e.target.closest && e.target.closest('[data-drawer-close]')) { close(); }
        });
        // Фаза перехвата: пока поверх панели открыта модалка («нет доступа / скоро»),
        // Esc и Tab принадлежат ей — панель остаётся открытой.
        document.addEventListener('keydown', function (e) {
            if (drawer.hidden || document.querySelector('.overlay.open')) { return; }
            if (e.key === 'Escape' || e.key === 'Esc') { close(); return; }
            if (e.key !== 'Tab') { return; }
            // Фокус не выходит из открытой панели.
            var focusable = panel.querySelectorAll('a[href], button, summary, [tabindex]:not([tabindex="-1"])');
            if (!focusable.length) { return; }
            var first = focusable[0];
            var last = focusable[focusable.length - 1];
            if (e.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
                e.preventDefault(); last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault(); first.focus();
            }
        }, true);
        if (window.matchMedia) {
            var wide = window.matchMedia('(min-width: 721px)');
            var onWide = function () { if (wide.matches) { close(); } };
            if (wide.addEventListener) { wide.addEventListener('change', onWide); } else if (wide.addListener) { wide.addListener(onWide); }
        }
    }

    /* ── Поля по роли (/admin/users, /admin/create-user) ──────────────────
       В форме с <select data-role-select> блок [data-role-fields="employee brigadier"] виден
       только при выбранной роли из списка; скрытые поля выключены (disabled) и не уходят
       на сервер. Без перезагрузки страницы. */
    function applyRoleFields(form, role) {
        Array.prototype.forEach.call(form.querySelectorAll('[data-role-fields]'), function (block) {
            var show = block.getAttribute('data-role-fields').split(/\s+/).indexOf(role) !== -1;
            block.hidden = !show;
            Array.prototype.forEach.call(block.querySelectorAll('input, select, textarea'), function (field) {
                field.disabled = !show;
            });
        });
    }
    function initRoleFields() {
        Array.prototype.forEach.call(document.querySelectorAll('select[data-role-select]'), function (select) {
            var form = select.form;
            if (!form) { return; }
            select.addEventListener('change', function () { applyRoleFields(form, select.value); });
            applyRoleFields(form, select.value);
        });
    }

    /* ── Перепроверка формы договора (/admin/contracts/…) ────────────────
       Смена <select data-recheck="le|region|mvd"> отправляет форму с action=check: сервер
       перерисует её с реквизитами нового юрлица/региона, введённое уходит тем же POST.
       Поля «ввести на месте» старого юрлица (fix:le:) / региона (fix:region:) / адресата (fix:mvd:) не
       отправляются — иначе записались бы в новое. */
    function recheckForm(select) {
        var form = select.form;
        if (!form) { return; }
        var prefix = 'fix:' + select.getAttribute('data-recheck') + ':';
        Array.prototype.forEach.call(form.elements, function (field) {
            if (field.name && field.name.indexOf(prefix) === 0) { field.disabled = true; }
        });
        var action = document.createElement('input');
        action.type = 'hidden'; action.name = 'action'; action.value = 'check';
        form.appendChild(action);
        form.submit();
    }
    function initRecheck() {
        Array.prototype.forEach.call(document.querySelectorAll('form[data-recheck-form] select[data-recheck]'), function (select) {
            select.addEventListener('change', function () { recheckForm(select); });
        });
    }

    // textarea[data-autogrow]: высота по тексту (от rows), длинный адрес виден целиком.
    // Внутри свёрнутого <details> высоту не измерить — пересчёт при раскрытии.
    function fitArea(area) {
        if (!area.offsetParent) return;
        area.style.height = 'auto';
        area.style.height = area.scrollHeight + 2 + 'px';
    }

    function initAutogrow() {
        var areas = document.querySelectorAll('textarea[data-autogrow]');
        if (!areas.length) return;
        Array.prototype.forEach.call(areas, function (area) {
            area.addEventListener('input', function () { fitArea(area); });
            fitArea(area);
        });
        document.addEventListener('toggle', function (event) {
            if (event.target.open) Array.prototype.forEach.call(event.target.querySelectorAll('textarea[data-autogrow]'), fitArea);
        }, true);
    }

    function init() { initAutogrow(); initLogoSpin(); initRipple(); initRowToggle(); initNoPlanPopup(); initLockedNav(); initDocPreview(); initBulkSelect(); initRail(); initDrawer(); initRoleFields(); initRecheck(); }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
