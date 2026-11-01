"""Update one release tag and all its required assets in a single atomic write."""
import json

from . import RewriteResult, register, rewrite_file_with
from ..parsers.github_release_pins import FILENAME, load_pins, validate_tool


@register(filenames=[FILENAME])
def rewrite_release_pins(path, edits):
    return rewrite_file_with(path, edits, _apply_one)


def _apply_one(text, edit):
    try:
        data = load_pins(text)
        extra = edit.extra or {}
        old, new = extra['old_tool'], extra['new_tool']
        validate_tool(new)
        if (data['tools'].get(edit.locator) != old or old['version'] != edit.old_value
                or new['version'] != edit.new_value or new['repository'] != old['repository']
                or new.get('release_tag_prefix') != old.get('release_tag_prefix')
                or {k: a['name'] for k, a in old['assets'].items()}
                != {k: a['name'] for k, a in new['assets'].items()}):
            raise ValueError('release pins changed since enumeration or asset identities differ')
        data['tools'][edit.locator] = new
        return json.dumps(data, indent=2) + '\n', RewriteResult(edit, new != old)
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        return text, RewriteResult(edit, False, f'release pins refused: {exc}')
