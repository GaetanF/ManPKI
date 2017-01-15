import os
import re
import polib
import json
from manpki.tools import log


def _convert_po_2_dict(po):
    """Convert po object to dictionary data structure (ready for JSON).
    """
    result = {}

    # result[''] = po.metadata.copy()

    for entry in po:
        if entry.obsolete:
            continue

        if entry.msgctxt:
            key = u'{0}\x04{1}'.format(entry.msgctxt, entry.msgid)
        else:
            key = entry.msgid

        if entry.msgstr:
            # result[key] = [None, entry.msgstr]
            result[key] = entry.msgstr
        elif entry.msgstr_plural:
            plural = [entry.msgid_plural]
            result[key] = plural
            ordered_plural = sorted(entry.msgstr_plural.items())
            for order, msgstr in ordered_plural:
                plural.append(msgstr)
    return result


def _po_convert(po_file, encoding=None, pretty_print=False):
    if encoding is None:
        po = polib.pofile(po_file,
                          autodetect_encoding=True)
    else:
        po = polib.pofile(po_file,
                          autodetect_encoding=False,
                          encoding=encoding)

    data = _convert_po_2_dict(po)

    if not pretty_print:
        result = json.dumps(data, ensure_ascii=False, sort_keys=True)
    else:
        result = json.dumps(data, sort_keys=True, indent=4 * ' ',
                            ensure_ascii=False)

    return result


def get_json_lang(lang):
    return _po_convert(get_path_lang(lang), encoding="UTF-8")


def get_path_lang(lang):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    return dir_path + os.path.sep + lang + os.path.sep + "LC_MESSAGES" + os.path.sep + lang + ".po"


def lang_is_defined(lang):
    if re.match("^[a-z]{2}(_([a-zA-Z]{2}){1,2})?_[A-Z]{2}.UTF-8$", lang):
        path = get_path_lang(lang)
        if os.path.exists(path):
            return True
    return False
