import os
import unittest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import CitizenshipRegime, Country
from country_helpers import build_country_matcher, match_country_id, parse_aliases


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class CountryAliasTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add(CitizenshipRegime(id=1, code="resident", name="Резидент"))
        self.s.add_all([
            Country(id=1, name="Россия", regime_id=1, is_active=True,
                    aliases="РФ, Российская Федерация"),
            Country(id=2, name="Белорусь", regime_id=1, is_active=True,
                    aliases="РБ, Беларусь"),
            Country(id=3, name="Армения", regime_id=1, is_active=True, aliases=None),
        ])
        self.s.commit()

    def tearDown(self):
        self.s.close()

    def test_parse_aliases_dedup_and_trim(self):
        self.assertEqual(parse_aliases(" РФ , Россия,РФ, "), ["РФ", "Россия"])
        self.assertEqual(parse_aliases(""), [])
        self.assertEqual(parse_aliases(None), [])

    def test_match_by_exact_name(self):
        self.assertEqual(match_country_id(self.s, "Россия"), 1)
        self.assertEqual(match_country_id(self.s, "армения"), 3)  # casefold

    def test_match_by_alias(self):
        self.assertEqual(match_country_id(self.s, "РФ"), 1)
        self.assertEqual(match_country_id(self.s, "рф"), 1)       # casefold
        self.assertEqual(match_country_id(self.s, "Беларусь"), 2)

    def test_unknown_and_empty(self):
        self.assertIsNone(match_country_id(self.s, "Аргентина"))
        self.assertIsNone(match_country_id(self.s, ""))
        self.assertIsNone(match_country_id(self.s, None))

    def test_name_wins_over_alias_collision(self):
        # Добавим страну, чьё ИМЯ совпадает с алиасом другой ("Беларусь" — алиас у id=2).
        self.s.add(Country(id=4, name="Беларусь", regime_id=1, is_active=True, aliases=None))
        self.s.commit()
        # Точное имя (id=4) должно выиграть над алиасом id=2.
        self.assertEqual(match_country_id(self.s, "Беларусь"), 4)

    def test_inactive_excluded_by_default(self):
        self.s.query(Country).filter(Country.id == 1).update({"is_active": False})
        self.s.commit()
        self.assertIsNone(match_country_id(self.s, "РФ"))

    def test_prebuilt_matcher_reused(self):
        matcher = build_country_matcher(self.s)
        self.assertEqual(match_country_id(self.s, "РФ", matcher=matcher), 1)
        self.assertEqual(match_country_id(self.s, "Армения", matcher=matcher), 3)


if __name__ == "__main__":
    unittest.main()
