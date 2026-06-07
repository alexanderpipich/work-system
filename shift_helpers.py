from utils import normalize_text


def is_no_plan_request_type(value) -> bool:
    request_type = normalize_text(value).lower()
    request_type = request_type.replace("ё", "е")
    return request_type in {"смена без плана", "смены без плана"}


def is_no_plan_shift(shift) -> bool:
    return is_no_plan_request_type(getattr(shift, "request_type", ""))
