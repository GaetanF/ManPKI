from flask import Blueprint

locale_route = Blueprint('locales', __name__, url_prefix='/locales')


@locale_route.route("/<locale>")
def get_locales(locale):
    locales = []
    return locales, 200
