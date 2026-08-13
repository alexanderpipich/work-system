"""Поиск ЧТС по началу строки (п.008): сужает список, не ломая фильтр слоёв."""

import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Rate
from routers.rates import _apply_layer, _apply_search, rates_query


class RatesSearchTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine)()
        for kwargs in (
            dict(service="1ур_Выкладка", format="ГМ", city="ЛО", hourly_rate=100),
            dict(service="2ур_Выкладка", format="ГМ", city="ЛО", hourly_rate=120),
            dict(service="1ур_Приёмка", format="ГМ", city="Moscow", hourly_rate=130),
            dict(service="2ур_Выкладка", format="ГМ", city="ЛО", store="ТК-7", hourly_rate=150),
            dict(service="3ур_Инвентаризация", format="СМ", city="ЛО",
                 employee_name="Иванова Т.М.", hourly_rate=200),
            dict(service="2ур Универсальные услуги", format="ГМ", city="ЛО", hourly_rate=140),
        ):
            self.session.add(Rate(**kwargs))
        self.session.commit()

    def _found(self, term, layer="all"):
        return _apply_layer(_apply_search(rates_query(self.session), term), layer).all()

    def test_empty_query_returns_everything(self):
        self.assertEqual(len(self._found("")), 6)
        self.assertEqual(len(self._found("   ")), 6)

    def test_matches_beginning_of_service(self):
        found = self._found("2ур")
        self.assertEqual(len(found), 3)
        self.assertTrue(all(r.service.startswith("2ур") for r in found))

    def test_level_prefix_is_not_part_of_the_name(self):
        """«2ур_» — префикс уровня, а не часть названия.

        Владелец набирает «Квалифицированные» и обязан увидеть
        «2ур_Квалифицированные» на всех уровнях: искать по началу ВСЕЙ строки
        здесь бесполезно, потому что название всегда начинается с префикса.
        """
        found = self._found("Выкладка")
        self.assertEqual(len(found), 3)
        self.assertTrue(all("Выкладка" in r.service for r in found))

    def test_space_also_separates_words(self):
        # Разделителем бывает и пробел: «2ур Универсальные услуги».
        self.assertEqual(len(self._found("Универсальные")), 1)
        self.assertEqual(len(self._found("услуги")), 1)

    def test_does_not_match_inside_a_word(self):
        # Середина слова — не начало: «клад» не должно вытаскивать «Выкладка».
        self.assertEqual(self._found("клад"), [])
        self.assertEqual(self._found("нвентар"), [])

    def test_matches_store_city_and_employee(self):
        self.assertEqual(len(self._found("ТК-7")), 1)
        self.assertEqual(len(self._found("Moscow")), 1)
        self.assertEqual(len(self._found("Иванова")), 1)

    def test_works_together_with_layer(self):
        # Один и тот же запрос, разные слои — пересечение, а не замена фильтра.
        self.assertEqual(len(self._found("2ур", "individual")), 1)
        self.assertEqual(len(self._found("2ур", "base")), 2)
        self.assertEqual(len(self._found("2ур", "all")), 3)

    def test_like_wildcards_are_escaped(self):
        # Без экранирования «%» вернул бы все строки, а «_» — любую одиночную букву.
        self.assertEqual(self._found("%"), [])
        self.assertEqual(self._found("_ур_Выкладка"), [])

    def test_ascii_case_is_ignored(self):
        # Кириллицу не проверяем: ILIKE регистронезависим по коллации БД, на
        # SQLite (сюита) это работает только для латиницы, на PostgreSQL — везде.
        self.assertEqual(len(self._found("moscow")), 1)
        self.assertEqual(len(self._found("MOSCOW")), 1)


if __name__ == "__main__":
    unittest.main()
