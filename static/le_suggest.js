/* Карточка юрлица (/admin/legal-entities): вычисляемые подсказки реквизитов руководителя.

   Подсказка — атрибут data-suggest поля: серым в пустом поле (placeholder) и строкой «→ …» под
   заполненным. Считается только из уже заполненных полей этого же юрлица:
   - «Подпись руководителя» ← ФИО в им. падеже: «Владимиров Иван Петрович» → «И.П. Владимиров»;
   - ФИО в род. падеже ← им. падеж и обратно — библиотекой petrovich (static/vendor/petrovich.min.js);
     не справилась (нет отчества, слово не склоняется обратно) — подсказки нет;
   - «Должность руководителя (род. падеж)» ← словарь частых вариантов: «генеральный директор» →
     «генерального директора» (подсказка из того, что введено в само поле).
   Принять: → в пустом поле или с курсором в конце, Tab в пустом поле. Без нажатия ничего не подставляется. */
(function (root) {
    'use strict';

    // Должность: слово в им. падеже → род. падеж. Подсказка — только если известны все слова.
    var TITLE_GENITIVE = {
        'генеральный': 'генерального', 'исполнительный': 'исполнительного', 'коммерческий': 'коммерческого',
        'финансовый': 'финансового', 'технический': 'технического', 'управляющий': 'управляющего',
        'директор': 'директора', 'президент': 'президента', 'председатель': 'председателя',
        'руководитель': 'руководителя'
    };
    // Род. падеж → кандидаты им. падежа; кандидат принимается, только если petrovich склоняет его обратно
    // в то же слово. Порядок — от более частых форм.
    var GENITIVE_ENDINGS = [
        ['ского', 'ский'], ['цкого', 'цкий'], ['ого', 'ой'], ['ого', 'ий'], ['ого', 'ый'], ['его', 'ий'],
        ['ича', 'ич'], ['ны', 'на'], ['ой', 'а'], ['ой', 'ая'], ['ей', 'яя'], ['ии', 'ия'], ['ьи', 'ья'],
        ['ы', 'а'], ['и', 'а'], ['и', 'я'], ['и', 'ь'], ['я', 'й'], ['я', 'ь'], ['а', '']
    ];

    function words(value) {
        return String(value || '').trim().split(/\s+/).filter(Boolean);
    }

    function signature(fio) {
        var parts = words(fio);
        if (parts.length < 2) return '';
        var initials = parts.slice(1, 3).map(function (word) { return word.charAt(0).toUpperCase() + '.'; }).join('');
        return initials + ' ' + parts[0];
    }

    function lib() {
        return root.petrovich || null;
    }

    function toGenitive(fio) {
        var p = lib();
        var parts = words(fio);
        if (!p || parts.length !== 3) return '';
        var gender = /ич$/i.test(parts[2]) ? 'male' : (/на$/i.test(parts[2]) ? 'female' : '');
        if (!gender) return '';
        try {
            var r = p({ gender: gender, last: parts[0], first: parts[1], middle: parts[2] }, 'genitive');
            return [r.last, r.first, r.middle].join(' ');
        } catch (e) {
            return '';
        }
    }

    function nominativeWord(gender, type, word) {
        var p = lib();
        var lower = word.toLowerCase();
        var candidates = [];
        GENITIVE_ENDINGS.forEach(function (pair) {
            if (lower.length > pair[0].length && lower.slice(-pair[0].length) === pair[0]) {
                candidates.push(word.slice(0, word.length - pair[0].length) + pair[1]);
            }
        });
        candidates.push(word);  // несклоняемое
        for (var i = 0; i < candidates.length; i++) {
            try {
                if (p[gender][type].genitive(candidates[i]) === word) return candidates[i];
            } catch (e) { /* следующий кандидат */ }
        }
        return '';
    }

    function toNominative(genitive) {
        var parts = words(genitive);
        if (!lib() || parts.length !== 3) return '';
        var gender = /ича$/i.test(parts[2]) ? 'male' : (/ны$/i.test(parts[2]) ? 'female' : '');
        if (!gender) return '';
        var result = [nominativeWord(gender, 'last', parts[0]), nominativeWord(gender, 'first', parts[1]),
                      nominativeWord(gender, 'middle', parts[2])];
        return result.every(Boolean) ? result.join(' ') : '';
    }

    function titleGenitive(title) {
        var parts = words(title.toLowerCase());
        if (!parts.length || !parts.every(function (word) { return TITLE_GENITIVE[word]; })) return '';
        return parts.map(function (word) { return TITLE_GENITIVE[word]; }).join(' ');
    }

    // Подсказки формы из её же полей: {имя поля: подсказка}.
    function suggestions(values) {
        var name = (values.director_name || '').trim();
        var genitive = (values.director_name_genitive || '').trim();
        var nominative = name || toNominative(genitive);
        return {
            director_name: name ? '' : toNominative(genitive),
            director_name_genitive: genitive ? '' : toGenitive(name),
            director_short: signature(nominative),
            director_title: titleGenitive(values.director_title || '')
        };
    }

    function refresh(form) {
        var values = {};
        Array.prototype.forEach.call(form.querySelectorAll('[data-suggest-field]'), function (input) {
            values[input.name] = input.value;
        });
        var computed = suggestions(values);
        Array.prototype.forEach.call(form.querySelectorAll('[data-suggest-field]'), function (input) {
            var suggest = computed[input.name] || '';
            if (suggest && suggest !== input.value) {
                input.setAttribute('data-suggest', suggest);
            } else {
                input.removeAttribute('data-suggest');
                suggest = '';
            }
            input.placeholder = suggest;
            var hint = form.querySelector('[data-suggest-hint="' + input.name + '"]');
            if (hint) hint.textContent = suggest && input.value ? '→ ' + suggest : '';
        });
    }

    // Принять подсказку по клавише. true — подставлено.
    function accept(input, event) {
        var suggest = input.getAttribute('data-suggest') || '';
        if (!suggest || input.value === suggest) return false;
        var empty = input.value === '';
        var atEnd = input.selectionStart === input.value.length && input.selectionEnd === input.value.length;
        var right = event.key === 'ArrowRight' && (empty || atEnd);
        var tab = event.key === 'Tab' && !event.shiftKey && empty;
        if (!right && !tab) return false;
        event.preventDefault();
        input.value = suggest;
        if (input.setSelectionRange) input.setSelectionRange(suggest.length, suggest.length);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
    }

    function init(form) {
        form.addEventListener('input', function () { refresh(form); });
        form.addEventListener('keydown', function (event) {
            if (event.target.hasAttribute && event.target.hasAttribute('data-suggest-field')) accept(event.target, event);
        });
        refresh(form);
    }

    var api = { signature: signature, toGenitive: toGenitive, toNominative: toNominative, titleGenitive: titleGenitive,
                suggestions: suggestions, refresh: refresh, accept: accept, init: init };
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
        return;
    }
    root.LeSuggest = api;
    function start() {
        Array.prototype.forEach.call(document.querySelectorAll('form[data-le-suggest]'), init);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
})(typeof window !== 'undefined' ? window : globalThis);
