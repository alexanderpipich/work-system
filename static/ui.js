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

    function init() { initLogoSpin(); initRipple(); initRowToggle(); }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
