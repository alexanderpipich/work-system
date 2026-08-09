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

    function init() { initLogoSpin(); initRipple(); }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
