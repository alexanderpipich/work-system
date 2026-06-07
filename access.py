from utils import normalize_text


def get_economist_cities(user):
    if not user.economist_stores:
        return []

    return [
        normalize_text(city)
        for city in user.economist_stores.split(",")
        if normalize_text(city)
    ]
