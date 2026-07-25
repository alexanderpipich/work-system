import datetime
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")

import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Service, Shift
from service_catalog import diagnose_uploaded_services
from routers.upload import _process_shift_dataframe


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class DiagnoseServicesTests(unittest.TestCase):
    def setUp(self):
        self.s = _session()
        self.s.add_all([Service(name="Уборка", is_active=True),
                        Service(name="Продавец", is_active=True)])
        self.s.commit()

    def test_unmatched_and_without_level(self):
        counts = {"2ур_Уборка": 5, "3ур_НетТакой": 2, "Продавец": 4, "5ур_РЦуслуга": 1}
        diag = diagnose_uploaded_services(self.s, counts)
        names = [u["name"] for u in diag["unmatched_services"]]
        # Уборка и Продавец есть в справочнике → не в unmatched
        self.assertNotIn("2ур_Уборка", names)
        self.assertNotIn("Продавец", names)
        self.assertIn("3ур_НетТакой", names)
        self.assertIn("5ур_РЦуслуга", names)
        # сортировка по числу смен убыв.
        self.assertEqual(diag["unmatched_services"][0]["name"], "3ур_НетТакой")
        self.assertEqual(diag["unmatched_services"][0]["shifts_count"], 2)
        # Продавец без уровня → 4 смены
        self.assertEqual(diag["services_without_level"], 4)

    def test_all_matched_empty(self):
        diag = diagnose_uploaded_services(self.s, {"2ур_Уборка": 3, "1ур_Продавец": 1})
        self.assertEqual(diag["unmatched_services"], [])


class UploadIntegrationTests(unittest.TestCase):
    """Диагностика информационная: смены грузятся всегда, отчёт несёт unmatched."""

    def _raw_df(self):
        return pd.DataFrame({
            "Магазин": ["Лента-1", "Лента-1"],
            "Формат": ["ГМ", "ГМ"],
            "Город": ["ЛО", "ЛО"],
            "Дата": ["20.07.2026", "20.07.2026"],
            "Тип заявки": ["Основные заказы", "Основные заказы"],
            "Услуга": ["2ур_Уборка", "3ур_НетТакой"],
            "ФИО сотрудника Исполнителя": ["Иванов", "Петров"],
            "ПланФакт минус неоплач. обед (в числовом формате), часы": [8, 6],
        })

    def test_shifts_loaded_and_unmatched_reported(self):
        s = _session()
        s.add(Service(name="Уборка", is_active=True))  # есть; «НетТакой» — нет
        s.commit()

        with patch("routers.upload.business_today", return_value=datetime.date(2026, 7, 25)):
            result = _process_shift_dataframe(s, self._raw_df())

        # Смены загружены несмотря на нераспознанную услугу
        self.assertEqual(result["added"], 2)
        self.assertEqual(s.query(Shift).count(), 2)
        # В отчёте — несматченная услуга с числом смен
        names = [u["name"] for u in result["unmatched_services"]]
        self.assertEqual(names, ["3ур_НетТакой"])
        self.assertEqual(result["unmatched_services"][0]["shifts_count"], 1)


if __name__ == "__main__":
    unittest.main()
