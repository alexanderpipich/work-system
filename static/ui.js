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

    function init() { initLogoSpin(); initRipple(); initRowToggle(); initNoPlanPopup(); }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
