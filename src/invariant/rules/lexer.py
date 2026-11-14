"""Tokenizer for the rule language."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import Diagnostic, RuleSyntaxError

PUNCTUATION = (
    "==", "!=", "<=", ">=",
    "{", "}", "(", ")", "[", "]", ",", ":", ".", "=", "<", ">", "+", "-", "*",
)  # fmt: skip
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0", "b": "\b", "f": "\f", "/": "/"}

#: Largest source accepted; rule files are small, and this bounds parser work.
MAX_SOURCE_CHARS = 256_000


@dataclass(frozen=True)
class Token:
    """A lexical token with its position."""
    kind: str  # "ident" | "string" | "number" | "punct" | "eof"
    value: str | int | float
    line: int
    col: int

    def describe(self) -> str:
        """The token as quoted in error messages."""
        if self.kind == "eof":
            return "end of input"
        if self.kind == "string":
            return f"string {str(self.value)!r}"
        return f"'{self.value}'"


def _error(message: str, line: int, col: int) -> RuleSyntaxError:
    return RuleSyntaxError([Diagnostic(message, line=line, col=col)])


def tokenize(source: str, *, line: int = 1, col: int = 1) -> list[Token]:
    """Tokens of ``source``. ``line``/``col`` give the position of its first character."""
    if len(source) > MAX_SOURCE_CHARS:
        raise _error(f"rule source is larger than {MAX_SOURCE_CHARS} characters", line, col)
    tokens: list[Token] = []
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        if ch == "\n":
            line, col, i = line + 1, 1, i + 1
            continue
        if ch in " \t\r":
            i, col = i + 1, col + 1
            continue
        if ch == "#" or source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
            continue
        start_line, start_col = line, col
        if ch.isalpha() or ch == "_":
            j = i
            while j < n and (source[j].isalnum() or source[j] == "_"):
                j += 1
            tokens.append(Token("ident", source[i:j], start_line, start_col))
            col, i = col + (j - i), j
            continue
        if ch.isdigit():
            j = i
            while j < n and source[j].isdigit():
                j += 1
            is_float = False
            if j + 1 < n and source[j] == "." and source[j + 1].isdigit():
                is_float = True
                j += 1
                while j < n and source[j].isdigit():
                    j += 1
            if j < n and (source[j].isalpha() or source[j] == "_"):
                raise _error(f"malformed number '{source[i : j + 1]}'", start_line, start_col)
            text = source[i:j]
            tokens.append(
                Token("number", float(text) if is_float else int(text), start_line, start_col)
            )
            col, i = col + (j - i), j
            continue
        if ch in "\"'":
            j, out = i + 1, []
            while True:
                if j >= n or source[j] == "\n":
                    raise _error("unterminated string (missing closing quote)", start_line, start_col)
                c = source[j]
                if c == ch:
                    break
                if c == "\\":
                    if j + 1 >= n:
                        raise _error("unterminated string", start_line, start_col)
                    esc = source[j + 1]
                    if esc == "u":
                        digits = source[j + 2 : j + 6]
                        if len(digits) != 4 or any(d not in "0123456789abcdefABCDEF" for d in digits):
                            raise _error(
                                "\\u must be followed by four hex digits",
                                start_line,
                                start_col + (j - i),
                            )
                        out.append(chr(int(digits, 16)))
                        j += 6
                        continue
                    if esc not in _ESCAPES:
                        raise _error(
                            f"unknown escape '\\{esc}' in string", start_line, start_col + (j - i)
                        )
                    out.append(_ESCAPES[esc])
                    j += 2
                    continue
                out.append(c)
                j += 1
            tokens.append(Token("string", "".join(out), start_line, start_col))
            col, i = col + (j + 1 - i), j + 1
            continue
        for p in PUNCTUATION:
            if source.startswith(p, i):
                tokens.append(Token("punct", p, start_line, start_col))
                col, i = col + len(p), i + len(p)
                break
        else:
            hint = " (use 'and', 'or', 'not')" if ch in "&|!" else ""
            raise _error(f"unexpected character {ch!r}{hint}", start_line, start_col)
    tokens.append(Token("eof", "", line, col))
    return tokens
