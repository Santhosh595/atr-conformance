"""A small YAML reader for ATR rule documents.

It handles the subset the rule corpus uses: nested mappings, lists, lists of
mappings, flow scalars, quoted strings and literal/folded block scalars.
Anything outside that subset raises YAMLError so callers report an unreadable
file instead of guessing at its meaning.
"""

from __future__ import annotations

import re

BLOCK_MARKERS = ("|", "|-", "|+", ">", ">-", ">+")
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


class YAMLError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    in_single = in_double = False
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
        elif in_double and ch == "\\":
            escaped = True
        elif ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _unquote(value: str):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        if value[0] == '"':
            try:
                return value[1:-1].encode().decode("unicode_escape")
            except UnicodeDecodeError as exc:
                raise YAMLError(f"bad quoted string: {exc}") from exc
        return value[1:-1].replace("''", "'")
    return value


def _split_flow(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current = ""
    in_single = in_double = False
    for ch in text:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append(current)
                current = ""
                continue
        current += ch
    if current.strip():
        parts.append(current)
    return parts


def _parse_flow(text: str):
    text = text.strip()
    if not text:
        return None
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_parse_flow(part) for part in _split_flow(inner)] if inner else []
    if text.startswith("{") and text.endswith("}"):
        inner = text[1:-1].strip()
        result = {}
        if not inner:
            return result
        for part in _split_flow(inner):
            key, sep, value = _top_level_split(part)
            if sep:
                result[str(_unquote(key))] = _parse_flow(value)
        return result
    if text in ("null", "Null", "NULL", "~"):
        return None
    if text in ("true", "True"):
        return True
    if text in ("false", "False"):
        return False
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return _unquote(text)


def _top_level_split(text: str) -> tuple[str, str | None, str]:
    in_single = in_double = False
    depth = 0
    for i, ch in enumerate(text):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == ":" and depth == 0 and (i + 1 == len(text) or text[i + 1] in " \t"):
                return text[:i], ":", text[i + 1 :]
    return text, None, ""


def _open_quote(text: str) -> str | None:
    index = 0
    quote = None
    escaped = False
    while index < len(text):
        ch = text[index]
        if quote == '"' and escaped:
            escaped = False
        elif quote == '"' and ch == "\\":
            escaped = True
        elif ch == quote:
            if ch == "'" and index + 1 < len(text) and text[index + 1] == "'":
                index += 1
            else:
                quote = None
        elif quote is None and ch in "\"'":
            quote = ch
        index += 1
    return quote


class _Reader:
    def __init__(self, text: str):
        self.lines = text.splitlines()
        self.pos = 0

    def next_token(self):
        while self.pos < len(self.lines):
            number = self.pos + 1
            raw = self.lines[self.pos]
            self.pos += 1
            if not raw.strip():
                continue
            content = _strip_comment(raw)
            if not content.strip() or content.strip() in ("---", "..."):
                continue
            indent = len(content) - len(content.lstrip(" "))
            content = content.strip()
            _, sep, raw_value = _top_level_split(content)
            quoted_value = bool(sep) and raw_value.strip().startswith(("\"", "'"))
            while quoted_value and (quote := _open_quote(content)) and self.pos < len(self.lines):
                continuation = _strip_comment(self.lines[self.pos]).strip()
                self.pos += 1
                if quote == '"' and content.endswith("\\"):
                    content = content[:-1] + continuation
                else:
                    content = content + " " + continuation
            if "\t" in content[:indent]:
                raise YAMLError(f"line {number}: tab indentation")
            return indent, content.strip(), number
        return None

    def peek(self):
        saved = self.pos
        token = self.next_token()
        self.pos = saved
        return token

    def block_scalar(self, parent_indent: int) -> str:
        collected = []
        while self.pos < len(self.lines):
            raw = self.lines[self.pos]
            indent = len(raw) - len(raw.lstrip(" "))
            if raw.strip() and indent <= parent_indent:
                break
            self.pos += 1
            collected.append(raw)
        widths = [len(line) - len(line.lstrip(" ")) for line in collected if line.strip()]
        base = min(widths) if widths else 0
        return "\n".join(line[base:] if line.strip() else "" for line in collected)

    def plain_scalar(self, value, parent_indent: int):
        if not isinstance(value, str):
            return value
        while True:
            following = self.peek()
            if following is None or following[0] <= parent_indent:
                break
            line = following[1]
            if line.startswith("- ") or line == "-":
                break
            key, sep, _ = _top_level_split(line)
            if sep and _KEY_RE.fullmatch(key.strip()):
                break
            self.next_token()
            value += " " + line
        return value

    def value(self, raw: str, key_indent: int, line_number: int):
        raw = raw.strip()
        if raw in BLOCK_MARKERS:
            return self.block_scalar(key_indent)
        if raw:
            return self.plain_scalar(_parse_flow(raw), key_indent)

        following = self.peek()
        if following is not None and (
            following[0] > key_indent
            or (following[0] == key_indent and following[1].startswith("- "))
        ):
            return self.parse_block(following[0])
        return None

    def parse_block(self, indent: int):
        token = self.peek()
        if token is None:
            return None
        if token[1].startswith("- ") or token[1] == "-":
            return self.parse_list(indent)
        return self.parse_map(indent)

    def parse_map(self, indent: int, first=None):
        result = {}
        token = first if first is not None else self.peek()
        while token is not None and token[0] == indent and not token[1].startswith("- "):
            _, content, line_number = token
            key, sep, raw_value = _top_level_split(content)
            if not sep or not _KEY_RE.fullmatch(key.strip()):
                raise YAMLError(f"line {line_number}: expected 'key: value'")
            self.next_token()
            result[key.strip()] = self.value(raw_value, indent, line_number)
            token = self.peek()
        return result

    def parse_list(self, indent: int) -> list:
        items = []
        while True:
            token = self.peek()
            if token is None or token[0] != indent:
                break
            content = token[1]
            if not (content.startswith("- ") or content == "-"):
                break
            line_number = token[2]
            rest = content[1:].strip()
            self.next_token()
            if not rest:
                following = self.peek()
                items.append(self.parse_block(following[0]) if following and following[0] > indent else None)
                continue
            if rest in BLOCK_MARKERS:
                items.append(self.block_scalar(indent))
                continue
            key, sep, raw_value = _top_level_split(rest)
            if sep and _KEY_RE.fullmatch(key.strip()):
                entry = {key.strip(): self.value(raw_value, indent + 2, line_number)}
                following = self.peek()
                if following is not None and following[0] > indent and not following[1].startswith("- "):
                    entry.update(self.parse_map(following[0]))
                items.append(entry)
            else:
                items.append(self.plain_scalar(_parse_flow(rest), indent))
        return items


def parse(text: str) -> dict:
    if "\ufeff" in text[:1]:
        text = text[1:]
    reader = _Reader(text)
    result = reader.parse_block(0)
    leftover = reader.peek()
    if leftover is not None:
        raise YAMLError(f"line {leftover[2]}: unexpected indentation")
    if not isinstance(result, dict):
        raise YAMLError("top level is not a mapping")
    return result
