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
        ):
            self.session.add(Rate(**kwargs))
        self.session.commit()

    def _found(self, term, layer="all"):
        return _apply_layer(_apply_search(rates_query(self.session), term), layer).all()

    def test_empty_query_returns_everything(self):
        self.assertEqual(len(self._found("")), 5)
        self.assertEqual(len(self._found("   ")), 5)

    def test_matches_beginning_of_service(self):
        found = self._found("2ур")
        self.assertEqual(len(found), 2)
        self.assertTrue(all(r.service.startswith("2ур") for r in found))

    def test_does_not_match_in_the_middle(self):
        """Услуги называются «1ур_Выкладка», «2ур_Выкладка»… — поиск по вхождению
        на «Выкладка» вернул бы все уровни сразу, ради чего фильтр и не нужен."""
        self.assertEqual(self._found("Выкладка"), [])

    def test_matches_store_city_and_employee(self):
        self.assertEqual(len(self._found("ТК-7")), 1)
        self.assertEqual(len(self._found("Moscow")), 1)
        self.assertEqual(len(self._found("Иванова")), 1)

    def test_works_together_with_layer(self):
        # Один и тот же запрос, разные слои — пересечение, а не замена фильтра.
        self.assertEqual(len(self._found("2ур", "individual")), 1)
        self.assertEqual(len(self._found("2ур", "base")), 1)
        self.assertEqual(len(self._found("2ур", "all")), 2)

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
