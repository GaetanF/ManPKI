import os
import json


def get_path_render():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return dir_path + os.path.sep + "manpki.json"


def get_content_render():
    if render_is_defined():
        path = get_path_render()
        try:
            with open(path, 'r') as content_file:
                render = json.load(content_file)
            return render
        except Exception:
            return ""
    return ""


def render_is_defined():
    path = get_path_render()
    if os.path.exists(path) and os.path.isfile(path):
        return True
    return False
