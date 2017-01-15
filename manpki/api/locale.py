import flask.json
from flask import Blueprint, json, request

localeroute = Blueprint('locales', __name__, url_prefix='/locales')


@localeroute.route("/<locale>")
def get_locales(locale):
    locales = []
    return locales, 200
