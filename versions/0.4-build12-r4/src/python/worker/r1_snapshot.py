"""Bounded, offline ZIP metadata and selected-text inspection; no extraction."""

from __future__ import annotations

import argparse
import ast
from array import array
from bisect import bisect_left, bisect_right
from collections import Counter, deque
import gzip
import hashlib
import io
import json
import ntpath
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
import time
import tokenize
import unicodedata
import warnings
import zipfile
import zlib


REPORT_FORMAT = "orchard-c-static-zip/1.2"
CHUNK_BYTES = 64 * 1024
PROBE_BYTES = 1024
LINK_CHAIN_LIMIT = 16
DEADLINE_SECONDS = 8.0
THOROUGH_SECONDS = 25.0
LIMITS = {
    "archive_bytes": 72 * 1024 * 1024,
    "central_directory_bytes": 1024 * 1024,
    "entries": 1024,
    "member_bytes": 16 * 1024 * 1024,
    "total_member_bytes": 64 * 1024 * 1024,
    "expansion_ratio": 100,
    "path_bytes": 512,
    "text_bytes_each": 4 * 1024 * 1024,
    "text_bytes_total": 32 * 1024 * 1024,
    "findings": 64,
    "evidence_chars": 240,
    "unknown_details": 256,
    "output_bytes": 3 * 1024 * 1024,
}
THOROUGH_LIMITS = {
    **LIMITS, "member_bytes": 32 * 1024 * 1024, "total_member_bytes": 128 * 1024 * 1024,
    "central_directory_bytes": 2 * 1024 * 1024, "entries": 4096,
    "text_bytes_each": 16 * 1024 * 1024, "text_bytes_total": 64 * 1024 * 1024,
}
NESTED_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst", ".jar",
                   ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub"}
NESTED_ZIP_SUFFIXES = {".zip", ".whl"}
NESTED_STREAM_SUFFIXES = {".tar", ".gz", ".tgz"}
ZIP_HEADERS = (b"PK\x03\x04", b"PK\x05\x06")
MACHO_HEADERS = {b"\xce\xfa\xed\xfe": ("<", 28), b"\xcf\xfa\xed\xfe": ("<", 32),
                 b"\xfe\xed\xfa\xce": (">", 28), b"\xfe\xed\xfa\xcf": (">", 32)}
FAT_MACHO_HEADERS = {b"\xca\xfe\xba\xbe": (">", 20), b"\xca\xfe\xba\xbf": (">", 32),
                    b"\xbe\xba\xfe\xca": ("<", 20), b"\xbf\xba\xfe\xca": ("<", 32)}
NON_BINARY_DOCUMENT_SUFFIXES = {
    ".md", ".mdx", ".mdc", ".txt", ".rst", ".adoc", ".yaml", ".yml", ".json", ".toml", ".ini",
    ".cfg", ".conf", ".xml", ".html", ".htm", ".py", ".js", ".ts", ".sh",
}
# Recognized binary assets are SHA-only. Their names alone cannot select this path.
ASSET_HEADERS = {
    ".png": (b"\x89PNG\r\n\x1a\n",), ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"), ".ico": (b"\x00\x00\x01\x00",), ".icns": (b"icns",),
    ".woff": (b"wOFF",), ".woff2": (b"wOF2",), ".ttf": (b"\x00\x01\x00\x00",),
    ".otf": (b"OTTO",), ".tif": (b"II*\x00", b"MM\x00*"), ".tiff": (b"II*\x00", b"MM\x00*"),
}
CONTAINER_HEADERS = (b"PK\x03\x04", b"PK\x05\x06", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07",
                     b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd")
TEXT_MARKS = ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
              (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"), (b"\xef\xbb\xbf", "utf-8-sig"))
# These fixed patterns classify *suspected* instructions, including quotations.
# Input never supplies patterns, tools, callbacks, commands or authority.
RULES = tuple((name, re.compile(pattern, re.IGNORECASE | re.MULTILINE)) for name, pattern in (
    ("INSTRUCTION_OVERRIDE",
     r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above|system|developer)\s+(?:instructions?|prompts?|rules?)\b"
     r"|(?:先行|以前|前の|上位|システム|開発者)(?:の)?(?:指示|命令|ルール)[^\n]{0,24}(?:無視|上書き)"
     r"|(?:これまで|今まで|上記|既存)(?:の)?[ \t　]*(?:(?:すべて|全て)の[ \t　]*)?(?:指示|命令|ルール)"
     r"(?:[ \t　]*[はをも])?[ \t　]*(?:、[ \t　]*)?(?:(?:すべて|全て)[ \t　]*(?:[を、][ \t　]*)?)?"
     r"(?:無視|上書き)(?=[ \t　]*(?:し(?:て|ろ|なさい)|せよ|する(?:こと|ように)|[。．！？.!?」』\r\n]|\Z))"),
    ("ROLE_SPOOFING", r"^[ \t]*(?:\[(?:system|developer)\]|<\|im_start\|>(?:system|developer)|(?:system|developer)[ \t]*:)|(?:AI|アシスタント|解析者|レビュアー)(?:への|向けの|の)(?:新しい|最優先の)?指示"),
    ("AUTHORITY_SPOOFING", r"\b(?:approval|authority|permission)\s+(?:is\s+)?(?:granted|approved)\b|\bowner\s+(?:has\s+)?(?:already\s+)?approved\b|(?:承認|許可)(?:は|が)?(?:取得済み|承認済み|付与済み)"),
    ("PRIVILEGE_REQUEST", r"\b(?:grant|enable|request|obtain)\b[^\n]{0,70}\b(?:admin(?:istrator)?|root|elevated|permissions?|privileges?)\b|\bsudo\b|(?:管理者|root|追加)(?:の)?権限[^\n]{0,30}(?:付与|取得|要求|許可)"),
    ("DATA_TRANSMISSION_REQUEST", r"\b(?:send|upload|transmit|email|post)\b[^\n]{0,120}(?:\b(?:secrets?|api[ _-]?keys?|tokens?|credentials?|private[ _-]?files?|environment[ _-]?variables?)\b)|(?:秘密|認証情報|APIキー|トークン|環境変数)[^\n]{0,80}(?:送信|アップロード|外部へ)"),
    ("TOOL_EXECUTION_REQUEST", r"\b(?:run|execute|invoke|call)\s+(?:the\s+)?(?:shell|terminal|command|tool|curl|bash|python|browser)\b|(?:シェル|コマンド|ツール)[^\n]{0,30}(?:実行|呼び出し)"),
    ("FINDING_SUPPRESSION", r"\b(?:hide|suppress|omit|conceal)\b[^\n]{0,70}\b(?:findings?|(?:security|inspection)\s+warnings?|injection|prompt_manipulation)\b|(?:所見|警告|検出結果)[^\n]{0,30}(?:隠|抑制|報告しない)"),
))

# Earlier spellings also occur in distribution archives.
DETECTOR_DEFINITION_ALIASES = {
    "DATA_TRANSMISSION_REQUEST": (r"(?:\b(?:secrets?", r"(?:https?://|\b(?:secrets?"),
    "FINDING_SUPPRESSION": (r"|(?:security|inspection)\s+warnings?|", r"|warnings?|"),
}
DETECTOR_DEFINITION_LITERALS = {
    category: frozenset((pattern.pattern, pattern.pattern.replace(*DETECTOR_DEFINITION_ALIASES[category], 1)))
    if category in DETECTOR_DEFINITION_ALIASES else frozenset((pattern.pattern,))
    for category, pattern in RULES
}
DETECTOR_LITERAL_MAX_BYTES = 128 * 1024
ZLIB_LICENSE_HEADER = ("# Permission is granted to anyone to use this software for any purpose,\n"
                       "# including commercial applications, and to alter it and redistribute it\n"
                       "# freely, subject to the following restrictions:")
ROLE_FIELD_MAX_BYTES = 128 * 1024
ROLE_FIELD_MAX_LINES = 4096
ROLE_FIELD_TYPES = frozenset(("str", "int", "bool", "float", "bytes"))
ROLE_FIELD_ROW = re.compile(
    r"^(?P<role>[ \t]{1,32}(?P<name>system|developer)[ \t]{0,4}:)[ \t]{1,8}"
    r"(?:str|int|bool|float|bytes)(?:[ \t]{0,8}=[ \t]{0,8}(?:None|True|False))?[ \t]{0,8}\r?$",
    re.MULTILINE,
)

# Generic shell and privilege language is common in ordinary developer documentation.
# Keep high-confidence role/authority/override findings independent of this context.
AGENT_CONTEXT = re.compile(
    r"\b(?:AI (?:assistant|agent)|language model|coding agent|as (?:the|an?) assistant)\b"
    r"|(?:AI|アシスタント|エージェント)(?:への|向けの|は|に対して)", re.IGNORECASE)
CONTEXTUAL = {"PRIVILEGE_REQUEST", "TOOL_EXECUTION_REQUEST"}
CONTRACT_AUTHORITY_PHRASE = re.compile(
    r"\b(?:without[ \t]+limiting|subject[ \t]+to|pursuant[ \t]+to|under|in[ \t]+accordance[ \t]+with)"
    r"[ \t]+the[ \t]+$", re.IGNORECASE)
CONTRACT_AUTHORITY_CITATION = re.compile(
    r"[ \t]+to[ \t]+(?:the[ \t]+)?(?P<party>[a-z][a-z -]{0,48}?)[ \t]+"
    r"(?:in|under|by|pursuant[ \t]+to)[ \t]+(?:section|article|clause)[ \t]+\d", re.IGNORECASE)
AGENT_GRANTEE = re.compile(r"\b(?:you|yourself|ai|llm|assistant|model|chatbot|coding agent)\b", re.IGNORECASE)
TRANSMISSION_PROHIBITION = re.compile(
    r"\b(?:never|do[ \t]+not|don['’]t|(?:must|should|shall|may|can)[ \t]+not|cannot|can['’]t)"
    r"[ \t]+(?:[*_`]{1,2})?$", re.IGNORECASE)
TRANSMISSION_OBJECT_PROHIBITION = re.compile(r"[ \t]+no\b(?![ \t]+(?:fewer|less)\b)", re.IGNORECASE)
TRANSMISSION_NOT_DESCRIBED = re.compile(
    r"\b(?:does[ \t]+not|doesn['’]t|did[ \t]+not|didn['’]t)[ \t]+"
    r"(?:define|specify|describe)[ \t]+how[ \t]+to[ \t]+$", re.IGNORECASE)
TRANSMISSION_NOT_REQUIRED = re.compile(
    r"\b(?:does[ \t]+not|doesn['’]t|do[ \t]+not|don['’]t)[ \t]+have[ \t]+to[ \t]+$", re.IGNORECASE)
EMAIL_FIELD_LIST = re.compile(
    r"email[ \t]+(?:address(?:es)?|local[- ]parts?)\b[^.;!?<>\n]{0,116}?"
    r"[ \t]+(?:is|are|was|were)\b", re.IGNORECASE)
TRANSMISSION_CLAUSE_QUALIFIER = re.compile(r"\b(?:to|via|using|because|until|when|if)\b", re.IGNORECASE)
TRANSMISSION_REMAINING_CASES = re.compile(r"\bthe[ \t]+rest[ \t]+$", re.IGNORECASE)
TRANSMISSION_OR_NOTHING = re.compile(r"[ \t]+or[ \t]+nothing\b", re.IGNORECASE)
HTTP_METHOD_ARGUMENTS = re.compile(
    r"(?P<method>['\"])post(?P=method)[ \t]*,[ \t]*(?P<path>['\"])(?:/|v\d+/)"
    r"[a-z0-9_/.-]+(?P=path)[ \t]*,[ \t]*[a-z_]\w*[ \t]*=", re.IGNORECASE)
WRAPPED_HELP_DESCRIPTION = re.compile(
    r"[a-z][ -~\t]{0,180}\b(?:a|the|their|its)[ \t]+help[ \t]*\r?\n"
    r"(?P<label>system:)[ \t]+(?:they (?:made|built|designed)|it (?:uses|opens|provides))"
    r"[ \t]+(?:the|a|its)[ \t]+help (?:window|buffer|pane)\b(?:[ \t]+[a-z][a-z-]*){0,8}[ \t]*\."
    r"(?:[ \t]+you can (?:use|navigate|read|scroll)(?:[ \t]+[a-z]+){1,6}\.?)?[ \t]*\r?", re.IGNORECASE)
VIM_POST_KEYWORD_LIST = re.compile(
    r"post(?:\\\|[a-z_]\w{0,48}(?:\\%\([a-z_]\w{0,48}\\\)\\\?)?)+", re.IGNORECASE | re.ASCII)
VIM_REGION_PATTERN = re.compile(
    r'[ \t]*syn(?:tax)?[ \t]+region[ \t]+[a-zA-Z_]\w{0,63}[ \t]*\r?\n'
    r'[ \t]*\\[ \t]+(?:start|skip|end)[ \t]*=[ \t]*"(?P<pattern>(?:[^"\\\r\n]|\\[^\r\n]){1,1024})"[ \t]*\r?',
    re.ASCII)
VIM_KEYMAP_MAX_BYTES = 64 * 1024
VIM_LOAD_KEYMAP = re.compile(rb"^loadkeymap[ \t]*\r?$", re.MULTILINE)
VIM_SCRIPT_ENCODING = re.compile(rb"^scriptencoding[ \t]+([a-zA-Z0-9_-]+)[ \t]*\r?$", re.MULTILINE)
VIM_KEYMAP_CODECS = {b"cp1250": "cp1250", b"iso-8859-2": "iso-8859-2"}
VIM_KEYMAP_KEY = r"(\x16[!-/:-@\[-`{-~]|[^\x00-\x20\x7f])"
VIM_KEYMAP_ROW = re.compile(VIM_KEYMAP_KEY + r"[ \t]+" + VIM_KEYMAP_KEY + r"[ \t]*\r?")
JA_TRANSMISSION_PROHIBITION = re.compile(
    r"[ \t]*(?:は|も|を)?[ \t]*(?:(?:再開|実行)(?:は|も)?)?[ \t]*"
    r"(?:し(?:ない|ません|ては(?:いけ|なら)(?:ない|ません))|行わない|禁止|不可|できません)(?!のでは|わけでは)")
JA_ROLE_ATTRIBUTION = re.compile(r"(?:AI|アシスタント|解析者|レビュアー)の(?:新しい|最優先の)?指示", re.IGNORECASE)
JA_ROLE_NOUN = re.compile(r"(?:の)?(?:作成|履歴|記録|一覧|内容|分析|評価|例)")
JA_OPERATION_NOUN = re.compile(r"(?:の)?(?:主体|履歴|記録|結果|時刻|状態|状況|可否)")
JA_OVERRIDE_NON_DIRECTIVE = re.compile(
    r"[ \t　]{0,8}(?:しない(?:で(?:ください)?|こと|ように(?:してください)?)?|しません|するな|できない|できません|"
    r"しては(?:いけない|いけません|ならない|なりません)|"
    r"する(?:必要は(?:ない|ありません)|べきでは(?:ない|ありません)|(?:こと|場合)が(?:ある|あります)|"
    r"ことは(?:禁止(?:です|されています|します)|できません))|"
    r"し(?:た|ました|てい(?:る|た|ます|ました)))"
    r"(?=[ \t　]{0,8}(?:[。．！？.!?」』\r\n]|\Z))")
JA_OVERRIDE_QUOTE_LABEL = re.compile(r"(?:^|[。！？])[ \t　]*(?:[>#+*-][ \t　]+)?(?:例|文例|例文|引用|説明例)[ \t　]*[:：][ \t　]*$")
JA_OVERRIDE_QUOTE_TAIL = re.compile(
    r"[ \t　]*(?:という(?:例文|文例|例|引用|説明)(?:です|でした)|"
    r"と(?:書いてあります|記載されています|引用しました|説明しました))[ \t　]*[。．.!?！？]?[ \t　\r]*")
WORKFLOW_EMAIL_FIELD = re.compile(
    r"[ \t]{0,32}(?P<label>email):[ \t]+"
    r"\$\{\{[ \t]+secrets\.[A-Za-z_][A-Za-z_0-9]*[ \t]+\}\}[ \t]*\r?")
FORM_EXAMPLE_FIELD = re.compile(r"`([a-z_][a-z_0-9]*)=([^\r\n`]+)`")
FORM_EXAMPLE_SEPARATOR = re.compile(r"[ \t,、，]*(?:and|und|et|y|e|और|和|ve|и|і)?[ \t,、，]*")
RELATIVE_POST_PATH = re.compile(r"/(?!/)[A-Za-z_0-9./{}-]*")
CONFIGURATION_EMAIL_KIND = re.compile(
    r"email[ \t]+"
    r"(?:credentials|services|kimlik bilgileri)\b", re.IGNORECASE)
CONFIGURATION_ENUMERATION = re.compile(r"\bdatabase[ \t]+(?:URL(?:s|['’]leri)|credentials),[ \t]*$", re.IGNORECASE)
TOKEN_REQUEST_RESPONSE = re.compile(
    r"you send it (?:a|the) "
    r"token and it returns (?:an? |the )?(?:authenticated user|user record|user identity)\.",
    re.IGNORECASE)
TOKEN_ENDPOINT_CREDENTIAL_FIELDS = re.compile(
    r"send the `username` and `password` "
    r"in order to get a token", re.IGNORECASE)
CLIENT_FIELD_DESCRIPTION = re.compile(
    r"they will send the `[a-z_][a-z_0-9]*`, it will be stored in the database, "
    r"but [a-z ]{1,72} won['’]t be returned in the API to the clients\.", re.IGNORECASE)
OTLP_PROVIDER_DESCRIPTION = re.compile(
    r"環境変数にOTLPエンドポイントが設定されている場合、[A-Za-z_0-9]+は有効な各プロバイダーに、"
    r"その送信先のエクスポーターを追加します。既存のエクスポーターは、それぞれの送信先にデータを送信し続けます。")
FORM_EXAMPLE_KEYS = {
    "contact_type", "name", "notification_type",
    "email",
    "token",
}
ASCII_TRIGGERS = {
    "INSTRUCTION_OVERRIDE": ("ignore", "disregard", "override"),
    "ROLE_SPOOFING": ("system", "developer"),
    "AUTHORITY_SPOOFING": ("approval", "authority", "permission", "owner"),
    "PRIVILEGE_REQUEST": ("grant", "enable", "request", "obtain", "sudo"),
    "DATA_TRANSMISSION_REQUEST": ("send", "upload", "transmit", "email", "post"),
    "TOOL_EXECUTION_REQUEST": ("run", "execute", "invoke", "call"),
    "FINDING_SUPPRESSION": ("hide", "suppress", "omit", "conceal"),
}
LINE_SEPARATORS = str.maketrans({"\f": "\n", "\x85": "\n", "\u2028": "\n", "\u2029": "\n"})
JOINERS = frozenset("\u00ad\u180e\u200b\u200c\u200d\u2060\ufeff")
FILE_CITATION = re.compile(
    r"(?<!\S)\ue200filecite\ue202turn[0-9]{1,10}file[0-9]{1,10}"
    r"(?:\ue202L[0-9]{1,9}(?:-L[0-9]{1,9})?)?\ue201(?!\S)")
# Scan both interpretations of presentation marks. Allowing them in a document
# never removes the need for the ordinary instruction scan.
SCAN_MARKS = JOINERS | frozenset("\u200e\ue200\ue201\ue202") | frozenset(map(chr, range(0xf000, 0xf100)))
SCAN_MARK_PATTERN = re.compile("[\u00ad\u180e\u200b\u200c\u200d\u2060\ufeff\u200e\ue200-\ue202\uf000-\uf0ff]")
SCAN_MARK_SPACES = str.maketrans({c: " " for c in SCAN_MARKS})
SCAN_MARK_REMOVAL = str.maketrans({c: None for c in SCAN_MARKS})
# These Unicode 17 letters are reported as Cn by the bundled Unicode 16 tables.
# Keep the compatibility exception to assigned capital/small-letter ranges.
UNICODE_17_LETTERS = (
    "\ua7ce", "\ua7cf", "\U00016ea0", "\U00016eb8", "\U00016ebb", "\U00016ed3",
)
ASCII_CONTROL = re.compile(r"[\x00-\x08\x0b\x0e-\x1f\x7f]")
BINARY_CONTROL = re.compile(rb"[\x00-\x08\x0e-\x1f]")
INSTRUCTION_NAMES = {"agents", "claude", "instructions"}
INSTRUCTION_SUFFIXES = {"", ".md", ".txt", ".rst"}
SKILL_ROOTS = {".agents", ".claude", ".cursor", ".codex"}
ROO_MODE_RULES = re.compile(r"rules-[a-zA-Z0-9-]+")
ROO_MODE_ROOT = re.compile(r"\.roorules-[a-zA-Z0-9-]+")
CHARACTER_EVIDENCE_LIMIT = 64


def _instruction_path(name):
    """Keep the approved 11/17 path priority without restricting text selection."""
    path = Path(name)
    parts = path.parts
    suffix = path.suffix
    if name in {".windsurfrules", ".roorules"} or ROO_MODE_ROOT.fullmatch(name):
        return True
    if (path.name in {"AGENTS.override.md", "CLAUDE.local.md"}
            or parts[-2:] == (".github", "copilot-instructions.md")
            or path.name.casefold() == ".cursorrules"
            or (path.stem.casefold() in INSTRUCTION_NAMES and suffix.casefold() in INSTRUCTION_SUFFIXES)):
        return True
    if suffix == ".md" and parts[-3:-1] in {(".devin", "rules"), (".windsurf", "rules")}:
        return True
    if suffix in {".md", ".txt"} and (path.parent.name == ".clinerules" or (
            len(parts) > 2 and parts[0] == ".roo"
            and (parts[1] == "rules" or ROO_MODE_RULES.fullmatch(parts[1])))):
        return True
    if suffix == ".mdc" and parts[-3:-1] == (".cursor", "rules"):
        return True
    if len(path.name) > len(".instructions.md") and path.name.endswith(".instructions.md"):
        if any(parts[i:i + 2] == (".github", "instructions") for i in range(len(parts) - 2)):
            return True
    return path.name == "SKILL.md" and (
        parts[-4:-2] == (".github", "skills") or any(
            parts[i] in SKILL_ROOTS and parts[i + 1] == "skills" for i in range(len(parts) - 3))
    )


def _text_order(item, limits):
    info, entry = item
    unavailable = bool(entry["issues"]) or info.file_size > limits["text_bytes_each"]
    instruction = not unavailable and _instruction_path(info.orig_filename)
    return unavailable, not instruction, info.orig_filename, entry["index"]


def _unknown(report, code, entry=None):
    report["_reasons"][code] += 1
    item = {"code": code}
    if entry is not None:
        item["entry_index"] = entry["index"]
        entry["issues"].append(code)
    else:
        report["_archive_reasons"][code] += 1
    unknowns = report["unknown_conditions"]
    if len(unknowns) < LIMITS["unknown_details"]:
        unknowns.append(item)
        return item
    elif len(unknowns) == LIMITS["unknown_details"]:
        unknowns.append({"code": "ADDITIONAL_UNKNOWN_CONDITIONS"})
    return None


STRUCTURE_REASONS = (
    "MALFORMED_", "ZIP64_", "MULTI_DISK_", "CONTAINER_LAYOUT_", "CENTRAL_DIRECTORY_",
    "ENTRY_COUNT_", "UNSAFE_OR_", "DUPLICATE_OR_", "ZIP_LINK_TARGET_EXTERNAL", "ZIP_LINK_PATH_CONFLICT", "ZIP_FLAGS_",
    "COMPRESSION_", "ZIP_VERSION_", "DIRECTORY_PAYLOAD_", "LOCAL_", "MEMBER_SPAN_",
    "STORED_SIZE_", "MEMBER_STREAM_", "MEMBER_LENGTH_", "ZIP_UNREADABLE_", "PATH_SIZE_",
    "TAR_STRUCTURE_", "GZIP_STRUCTURE_", "EXPANSION_RATIO_", "NESTED_EXPANSION_RATIO_",
)
class _Budget:
    def __init__(self, deadline, thorough=False, on_resolved=None):
        self.deadline = deadline
        self.limits = THOROUGH_LIMITS if thorough else LIMITS
        self.depth = 4 if thorough else 1
        self.member_bytes = self.limits["total_member_bytes"]
        self.text_bytes = self.limits["text_bytes_total"]
        self.entries = self.limits["entries"]
        self.central_bytes = self.limits["central_directory_bytes"]
        self.on_resolved = on_resolved
        self.ancestors = []

    def resolved(self, entry, covered=False):
        """Notify only for an inspected member or a proven scope exclusion."""
        if self.on_resolved is None:
            return
        issues = entry["issues"]
        if covered or entry["text_status"] != "UNINSPECTABLE" or (
                len(issues) == 1 and issues[0] in TEXT_FORMAT_EXCLUSIONS):
            self.on_resolved((*self.ancestors, entry["index"]))


TEXT_FORMAT_EXCLUSIONS = frozenset({
    "NON_PLAIN_TEXT_DOCUMENT_UNINSPECTED", "EXECUTABLE_BODY_UNINSPECTED", "SQLITE_BODY_UNINSPECTED",
    "OPAQUE_BINARY_UNINSPECTED", "ENCRYPTED_ENTRY_UNSUPPORTED", "LINK_OR_SPECIAL_FILE_UNSUPPORTED",
    "ZIP_LINK_TARGET_INVALID", "ZIP_LINK_TARGET_UNRESOLVED", "ZIP_LINK_TARGET_CYCLE",
    "UNSUPPORTED_ARCHIVE_BODY_OUT_OF_SCOPE",
})


def _instruction_scope(report, nested, text_files):
    archive_reasons = dict(report.pop("_archive_reasons"))
    children = report.pop("_inner_instruction_items")
    checked = report.pop("_checked_documents")
    child_checked = report.pop("_inner_checked_documents")
    known_other_archives = {row["entry_index"] for row in nested if row["kind"] == "OTHER_ARCHIVE"}
    items = []
    for entry in report["entries"]:
        index = entry["index"]
        if index in children:
            items.extend(children[index])
            continue
        status = entry["text_status"]
        if status in {"DIRECTORY", "READ_TEXT"}:
            continue
        reasons = Counter(entry["issues"])
        excluded = False
        if status == "SHA_ONLY":
            reasons["INTERNAL_LINK_REFERENCE" if entry.get("link", {}).get("status") == "INTERNAL"
                    else "TEXT_BODY_NOT_APPLICABLE"] = 1
            excluded = True
        elif len(entry["issues"]) == 1:
            code = entry["issues"][0]
            excluded = code in TEXT_FORMAT_EXCLUSIONS or (
                code == "NESTED_FORMAT_UNSUPPORTED" and index in known_other_archives)
        items.append({"entry_index": index, "disposition": "OUT_OF_SCOPE" if excluded else "UNREAD",
                      "reasons": dict(reasons) or {"MEMBER_NOT_READ": 1}})
    status = (
        "DETECTED" if report["findings"] else
        "INCOMPLETE" if archive_reasons or any(row["disposition"] == "UNREAD" for row in items) else
        "NO_FINDINGS" if text_files else "NO_TARGETS"
    )
    return {"status": status, "checked_files": text_files, "archive_reasons": archive_reasons, "items": items,
            "checked_members": [{"entry_index": index} for index in sorted(checked)] + child_checked}



def _finish(report):
    unknown = bool(report["unknown_conditions"])
    reasons = dict(report.pop("_reasons"))
    nested = report.pop("_nested")
    unread = report["coverage"]["uninspected_files"]
    completed_nested = sum(item["status"] == "COMPLETE" for item in nested)
    nested_text = sum(item["text_files_read"] for item in nested)
    outer_text = report["coverage"]["text_files_read"]
    outer_unresolved = unread - (len(nested) - completed_nested)
    outer_complete = not outer_unresolved and not (
        not report["entries"] and unknown)
    directory_parsed = report.pop("_directory_parsed", False)
    report["scope_detail"] = {
        "structure_status": "INCOMPLETE" if not report["input"] or not directory_parsed
        or any(code.startswith(STRUCTURE_REASONS) for code in reasons) else "CHECKED",
        "outer_text_status": ("INCOMPLETE" if not outer_complete else
                              "CHECKED" if outer_text else "NO_TEXT_IN_SCOPE"),
        "ordinary_out_of_scope": report["coverage"]["hash_only_files"] - completed_nested,
        "outer_unresolved": outer_unresolved,
        "nested": nested,
        "blocking_reasons": reasons,
    }
    report.pop("_finding_limit", None)
    report.pop("_thorough", None)
    report["inspection_status"] = "UNKNOWN" if unknown else "COMPLETE"
    report["prompt_injection"] = (
        "DETECTED" if report["findings"] else
        "UNINSPECTABLE" if unknown else
        "NOT_DETECTED" if outer_text or nested_text else "NO_TEXT_IN_SCOPE"
    )
    report["gate"] = "HOLD" if unknown or report["findings"] else "CAP"
    report["instruction_scope"] = _instruction_scope(report, nested, outer_text + nested_text)
    return report


def _directory_bound(data, limits):
    """Bound actual CD records *before* ZipFile allocates ZipInfo objects.

    ZipFile remains the ZIP parser. This preflight supports ordinary, single-disk
    ZIPs only; ZIP64, split/SFX/trailing containers return UNKNOWN.
    """
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise ValueError("MALFORMED_ZIP_END")
    _, disk, cd_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4s4H2LH", data, end)
    if 65535 in (disk_count, count) or 0xFFFFFFFF in (size, offset):
        raise ValueError("ZIP64_UNSUPPORTED")
    if disk or cd_disk or disk_count != count:
        raise ValueError("MULTI_DISK_UNSUPPORTED")
    if count > limits["entries"]:
        raise ValueError("ENTRY_COUNT_LIMIT")
    if size > limits["central_directory_bytes"]:
        raise ValueError("CENTRAL_DIRECTORY_SIZE_LIMIT")
    if (end + 22 + comment != len(data) or offset + size != end
            or (count and not data.startswith(b"PK\x03\x04"))):
        raise ValueError("CONTAINER_LAYOUT_UNSUPPORTED")
    pos, actual = offset, 0
    while pos < end:
        if pos + 46 > end or data[pos:pos + 4] != b"PK\x01\x02":
            raise ValueError("MALFORMED_CENTRAL_DIRECTORY")
        lengths = struct.unpack_from("<3H", data, pos + 28)
        pos += 46 + sum(lengths)
        actual += 1
        if actual > limits["entries"]:
            raise ValueError("ENTRY_COUNT_LIMIT")
    if pos != end or actual != count:
        raise ValueError("CENTRAL_DIRECTORY_COUNT_MISMATCH")
    return offset, count, size


def _display_path(name):
    clean = "".join(char if ord(char) >= 32 and ord(char) != 127 else "\ufffd" for char in name)
    return clean.encode("utf-8", errors="replace")[:LIMITS["path_bytes"]].decode("utf-8", errors="ignore")


def _asset(name, sample):
    leaf = name.rsplit("/", 1)[-1]
    suffix = Path(leaf).suffix.casefold()
    if leaf == ".DS_Store":
        recognized = sample.startswith(b"\x00\x00\x00\x01Bud1")
    elif leaf.startswith("._"):
        recognized = sample.startswith(b"\x00\x05\x16\x07\x00\x02\x00\x00") and len(sample) >= 26
    elif suffix == ".webp":
        recognized = sample.startswith(b"RIFF") and sample[8:12] == b"WEBP"
    else:
        recognized = sample.startswith(ASSET_HEADERS.get(suffix, ()))
    if not recognized:
        return False
    if BINARY_CONTROL.search(sample):
        return True
    try:
        sample.decode("utf-8")
    except UnicodeError:
        return True
    return False


def _executable_format(payload, size):
    header = bytes(payload[:4])
    if header in MACHO_HEADERS:
        order, start = MACHO_HEADERS[header]
        if len(payload) < start + 8:
            return None
        cpu, _, kind, commands, command_bytes = struct.unpack_from(order + "5I", payload, 4)
        first, first_size = struct.unpack_from(order + "2I", payload, start)
        if (cpu and 1 <= kind <= 12 and commands and 8 * commands <= command_bytes <= size - start
                and first and 8 <= first_size <= command_bytes and first_size % 4 == 0):
            return "MACH_O"
    elif header in FAT_MACHO_HEADERS and len(payload) >= 8:
        order, stride = FAT_MACHO_HEADERS[header]
        count, = struct.unpack_from(order + "I", payload, 4)
        end = 8 + stride * count
        if not 1 <= count <= 32 or end > len(payload):
            return None
        spans = []
        for pos in range(8, end, stride):
            cpu, _, offset, length, alignment = struct.unpack_from(order + ("IIQQI" if stride == 32 else "5I"),
                                                                   payload, pos)
            if not cpu or alignment > 30 or offset % (1 << alignment) or offset < end or length < 28 or offset + length > size:
                return None
            spans.append((offset, offset + length))
        spans.sort()
        if all(right <= next_left for (_, right), (next_left, _) in zip(spans, spans[1:])):
            return "MACH_O_UNIVERSAL"
    elif header == b"\x7fELF" and len(payload) >= 52:
        bits, byte_order, version = payload[4:7]
        if bits in (1, 2) and byte_order in (1, 2) and version == 1:
            length, offset = (52, 40) if bits == 1 else (64, 52)
            order = "<" if byte_order == 1 else ">"
            if len(payload) >= length and struct.unpack_from(order + "H", payload, offset)[0] == length:
                return "ELF"
    elif payload.startswith(b"MZ") and len(payload) >= 64:
        offset, = struct.unpack_from("<I", payload, 60)
        if 64 <= offset <= len(payload) - 24 and payload[offset:offset + 4] == b"PE\0\0":
            machine, sections = struct.unpack_from("<2H", payload, offset + 4)
            if machine and 1 <= sections <= 96:
                return "PE"
    return None


def _non_text_format(name, payload, size):
    if _instruction_path(name) or Path(name).suffix.casefold() in NON_BINARY_DOCUMENT_SUFFIXES:
        return None, None
    executable = _executable_format(payload[:PROBE_BYTES], size)
    if executable:
        return "EXECUTABLE_BODY_UNINSPECTED", executable
    if len(payload) >= 100 and payload.startswith(b"SQLite format 3\0"):
        page_size, = struct.unpack_from(">H", payload, 16)
        page_size = 65536 if page_size == 1 else page_size
        if (512 <= page_size <= 65536 and page_size & (page_size - 1) == 0
                and size >= page_size and size % page_size == 0 and all(n in (1, 2) for n in payload[18:20])
                and payload[21:24] == b"\x40\x20\x20"):
            return "SQLITE_BODY_UNINSPECTED", "SQLITE_3"
    return None, None


def _archive_sidecar(name, payload, size):
    # ditto appends the original suffix to AppleDouble files. A bounded
    # Finder-info record with an empty resource fork is ordinary metadata.
    if not name.rsplit("/", 1)[-1].startswith("._") or len(payload) != size or size < 50:
        return False
    if (not payload.startswith(b"\x00\x05\x16\x07\x00\x02\x00\x00")
            or payload[8:24] not in (bytes(16), b"Mac OS X        ") or payload[24:26] != b"\x00\x02"):
        return False
    kind, start, length, fork, end, fork_size = struct.unpack_from(">6I", payload, 26)
    return (kind, start, fork, end, fork_size) == (9, 50, 2, size, 0) and length == size - start


def _member_chunks(data, info, deadline):
    offset = info.header_offset
    start = offset + 30 + sum(struct.unpack_from("<2H", data, offset + 26))
    end = start + info.compress_size
    source = memoryview(data)
    decoder = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
    remaining = info.file_size
    for pos in range(start, end, CHUNK_BYTES):
        if time.monotonic() >= deadline:
            raise ValueError("MEMBER_DEADLINE")
        segment = source[pos:min(pos + CHUNK_BYTES, end)]
        if decoder is None:
            yield segment
            continue
        if decoder.eof:
            raise ValueError("MEMBER_STREAM_MISMATCH")
        while segment:
            if time.monotonic() >= deadline:
                raise ValueError("MEMBER_DEADLINE")
            decoded = decoder.decompress(segment, min(CHUNK_BYTES, remaining + 1))
            remaining -= len(decoded)
            if remaining < 0 or decoder.unused_data:
                raise ValueError("MEMBER_STREAM_MISMATCH")
            yield decoded
            segment = decoder.unconsumed_tail
    if decoder is not None and (not decoder.eof or remaining):
        raise ValueError("MEMBER_STREAM_MISMATCH")


def _read_member(data, info, deadline, text_limit):
    digest = hashlib.sha256()
    crc, size = 0, 0
    prefix = bytearray()
    keep = info.file_size if info.file_size <= text_limit else PROBE_BYTES
    for chunk in _member_chunks(data, info, deadline):
        size += len(chunk)
        crc = zlib.crc32(chunk, crc)
        digest.update(chunk)
        missing = keep - len(prefix)
        if missing > 0:
            prefix.extend(chunk[:missing])
    if size != info.file_size or crc != info.CRC:
        raise ValueError("MEMBER_LENGTH_OR_CRC_MISMATCH")
    return digest.hexdigest(), prefix


def _link_index(report, members, link_indices):
    """Index the verified ZIP namespace before any document or link body is read."""
    paths, directories, by_identity = {}, {""}, {}
    for info, entry in members:
        name = info.orig_filename.rstrip("/")
        if entry["issues"] or not name:
            continue
        paths[name] = entry["index"]
        identity = unicodedata.normalize("NFC", name).casefold()
        by_identity[identity] = name
        if info.is_dir():
            directories.add(name)
        parts = name.split("/")
        directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
    conflicts = set()
    directory_identities = {unicodedata.normalize("NFC", name).casefold() for name in directories}
    for info, entry in members:
        name = info.orig_filename.rstrip("/")
        if "DUPLICATE_OR_COLLIDING_PATH" in entry["issues"]:
            original = by_identity.get(unicodedata.normalize("NFC", name).casefold())
            if original is not None:
                conflicts.add(original)
        if name in paths and unicodedata.normalize("NFC", name).casefold() in directory_identities and not info.is_dir():
            if entry["index"] in link_indices:
                _unknown(report, "ZIP_LINK_PATH_CONFLICT", entry)
            conflicts.add(name)
    return paths, directories, conflicts


def _link_target(payload):
    try:
        value = payload.decode("utf-8")
    except UnicodeError:
        return "ZIP_LINK_TARGET_INVALID", ""
    if not value or any(unicodedata.category(char).startswith("C") for char in value):
        return "ZIP_LINK_TARGET_INVALID", ""
    if value.startswith(("/", "\\")) or ntpath.splitdrive(value)[0]:
        return "ZIP_LINK_TARGET_EXTERNAL", value
    if "\\" in value:
        return "ZIP_LINK_TARGET_INVALID", value
    return None, value


def _resolve_link(name, paths, directories, conflicts, links, payloads, deadline):
    """Resolve names solely against the archive index, including directory-link hops."""
    stack = name.split("/")[:-1]
    pending = deque(name.split("/")[-1:])
    active, hops = set(), 0
    while pending:
        if time.monotonic() >= deadline:
            return "MEMBER_DEADLINE", None
        part = pending.popleft()
        if isinstance(part, int):
            active.remove(part)
            continue
        parent = "/".join(stack)
        if parent not in directories or parent in conflicts:
            return "ZIP_LINK_TARGET_UNRESOLVED", None
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                return "ZIP_LINK_TARGET_EXTERNAL", None
            stack.pop()
            continue
        logical = "/".join([*stack, part])
        index = paths.get(logical)
        if logical in conflicts or (index is None and logical not in directories):
            return "ZIP_LINK_TARGET_UNRESOLVED", None
        if index not in links:
            stack.append(part)
            continue
        if index in active:
            return "ZIP_LINK_TARGET_CYCLE", None
        if hops >= LINK_CHAIN_LIMIT:
            return "ZIP_LINK_CHAIN_LIMIT", None
        if index not in payloads:
            return "ZIP_LINK_TARGET_UNRESOLVED", None
        reason, target = payloads[index]
        if reason:
            return reason, None
        active.add(index)
        hops += 1
        pending.appendleft(index)
        pending.extendleft(reversed(target.split("/")))
    return None, "/".join(stack) or "."


def _finish_links(report, members, path_index, links, payloads, budget):
    paths, directories, conflicts = path_index
    for info, entry in members:
        payload = payloads.get(entry["index"])
        if payload is None:
            continue
        name = info.orig_filename
        direct_error, raw_target = payload
        reason, target = ((direct_error, None) if direct_error else
                          _resolve_link(name, paths, directories, conflicts, links, payloads, budget.deadline))
        if reason:
            entry["link"] = {"status": "EXTERNAL" if reason == "ZIP_LINK_TARGET_EXTERNAL" else "UNRESOLVED"}
            if raw_target:
                entry["link"]["stored_target"] = _display_path(raw_target)
            _unknown(report, reason, entry)
            report["coverage"]["uninspected_files"] += 1
        else:
            target_index = paths.get(target)
            referent = report["entries"][target_index] if target_index is not None else None
            entry["link"] = {"status": "INTERNAL", "stored_target": _display_path(raw_target),
                             "resolved_target": _display_path(target),
                             "referent_text_status": referent["text_status"] if referent else "DIRECTORY"}
            entry["text_status"] = "SHA_ONLY"
            report["coverage"]["hash_only_files"] += 1
        budget.resolved(entry)


def _character_reason(character, category, name):
    if unicodedata.bidirectional(character) in {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"} or character in "\u061c\u200e\u200f":
        return "BIDIRECTIONAL_DISPLAY_CONTROL"
    if name.startswith("ZERO WIDTH"):
        return "ZERO_WIDTH_FORMAT_CHARACTER"
    return {"Cf": "FORMAT_CHARACTER_MAY_OBSCURE_TEXT", "Cc": "CONTROL_CHARACTER_IN_TEXT"}.get(
        category, "CHARACTER_VISIBILITY_UNKNOWN")


def _is_new_letter(character):
    latin_upper, latin_lower, capitals_start, capitals_end, small_start, small_end = UNICODE_17_LETTERS
    return latin_upper <= character <= latin_lower or capitals_start <= character <= capitals_end or small_start <= character <= small_end


def _symbol_delimiter(logical, offset):
    return (offset < 0 or offset >= len(logical) or logical[offset].isspace()
            or unicodedata.category(logical[offset]).startswith("P"))


def _character_warnings(source, logical, findings, remaining, deadline, literal_escapes=()):
    if logical.isascii() and not ASCII_CONTROL.search(logical):
        return [], 0, True
    citations = FILE_CITATION.finditer(logical)
    citation = None
    line_end = -1
    right_to_left = False
    finding_spans = [(hit["start_char"], hit["end_char"]) for hit in findings]
    details = []
    count = 0
    complete = True
    for offset, character in enumerate(logical):
        if offset % CHUNK_BYTES == 0 and time.monotonic() >= deadline:
            complete = False
            break
        if character in JOINERS:
            if not findings:
                continue
            category = unicodedata.category(character)
        elif character.isascii():
            if not ASCII_CONTROL.fullmatch(character) or offset in literal_escapes:
                continue
            category = "Cc"
        else:
            category = unicodedata.category(character)
            if not category.startswith("C"):
                continue
            if category == "Cn" and _is_new_letter(character):
                continue
            implicated = any(start <= offset < end for start, end in finding_spans)
            if not implicated and character == "\u200e":
                if offset >= line_end:
                    start = logical.rfind("\n", 0, offset) + 1
                    end = logical.find("\n", offset)
                    line_end = end if end >= 0 else len(logical)
                    right_to_left = any(unicodedata.bidirectional(char) in {"R", "AL", "AN"}
                                        for char in logical[start:line_end] if not char.isascii())
                if not right_to_left:
                    continue
            if not implicated and "\uf000" <= character <= "\uf0ff" and (
                    _symbol_delimiter(logical, offset - 1) or _symbol_delimiter(logical, offset + 1)):
                continue
            if not implicated and character in "\ue200\ue201\ue202":
                if citation is None or citation.end() <= offset:
                    citation = next(citations, None)
                    while citation is not None and citation.end() <= offset:
                        citation = next(citations, None)
                if citation is not None and citation.start() <= offset < citation.end():
                    continue
        count += 1
        if len(details) < remaining:
            name = unicodedata.name(character, "UNNAMED")
            details.append({
                "start_char": offset, "end_char": offset + 1,
                "line": source.count("\n", 0, offset) + 1, "column": offset - source.rfind("\n", 0, offset),
                "codepoint": f"U+{ord(character):04X}", "unicode_name": name, "unicode_category": category,
                "reason": _character_reason(character, category, name),
            })
    return details, count, complete


def _character_evidence(entry, condition, details, count, complete):
    condition.update({
        "path": entry["path"], "malicious_intent": "UNKNOWN",
        "reason": "Text visibility may be affected; legitimate Unicode use is possible.",
        "position_unit": "Unicode code points after decoding; offsets zero-based, line/column one-based",
        "character_warnings": details, "character_count": count,
        "character_count_complete": complete, "character_evidence_limit": CHARACTER_EVIDENCE_LIMIT,
        "character_evidence_truncated": not complete or count > len(details),
    })


def _japanese_variants(payload, iso_only=False):
    variants = []
    codecs = ("iso2022_jp",) if iso_only else ("cp932", "euc_jp")
    for codec in codecs:
        try:
            decoded = payload.decode(codec)
        except UnicodeError:
            continue
        if (sum(1 for char in decoded if "\u3041" <= char <= "\u30ff" or "\u3400" <= char <= "\u9fff") >= 2
                and not any(unicodedata.category(char).startswith("C") and char not in "\r\n\t\f" for char in decoded)
                and decoded not in [text for _, text in variants]):
            variants.append((codec, decoded))
    return variants


def _vim_keymap_header(name, payload):
    if len(payload) > VIM_KEYMAP_MAX_BYTES or not name.casefold().endswith(".vim"):
        return False, None
    load = VIM_LOAD_KEYMAP.search(payload, 0, min(len(payload), PROBE_BYTES))
    if load is None:
        return False, None
    declarations = VIM_SCRIPT_ENCODING.findall(payload, 0, load.start())
    codec = VIM_KEYMAP_CODECS.get(declarations[0].lower()) if len(declarations) == 1 else None
    return True, codec


def _vim_literal_escape_offsets(text):
    # A keymap table accepts Ctrl-V followed by one literal punctuation key.
    # Only that character in a two-key mapping row is exempt from the warning.
    match = re.search(r"(?m)^loadkeymap[ \t]*\r?$", text)
    if match is None:
        return ()
    offset = match.end() + 1
    escapes = set()
    for line in text[offset:].split("\n"):
        if "\x16" in line and (row := VIM_KEYMAP_ROW.fullmatch(line)):
            if all(key.startswith("\x16") or key.isprintable() for key in row.groups()):
                escapes.update(offset + row.start(column) for column in (1, 2)
                               if row[column].startswith("\x16"))
        offset += len(line) + 1
    return escapes


def _read_text(report, entry, name, payload, size, budget):
    entry["text_status"] = "UNINSPECTABLE"
    deadline = budget.deadline
    if payload.startswith(b"%PDF-"):
        _unknown(report, "NON_PLAIN_TEXT_DOCUMENT_UNINSPECTED", entry)
        return
    if not size or _asset(name, payload):
        entry["text_status"] = "SHA_ONLY"
        report["coverage"]["hash_only_files"] += 1
        return
    # _read_member has already checked the complete payload's length and CRC.
    # Format evidence uses the retained prefix and no additional read budget.
    reason, binary_format = _non_text_format(name, payload, size)
    if reason:
        entry["non_text_format"] = binary_format
        _unknown(report, reason, entry)
        return
    if size > budget.limits["text_bytes_each"]:
        _unknown(report, "TEXT_BYTE_LIMIT", entry)
        return
    if size > budget.text_bytes:
        _unknown(report, "TEXT_TOTAL_BUDGET_LIMIT", entry)
        return
    budget.text_bytes -= size
    encoding = next((codec for mark, codec in TEXT_MARKS if payload.startswith(mark)), "utf-8")
    keymap, declared_codec = _vim_keymap_header(name, payload) if encoding == "utf-8" else (False, None)
    variants = _japanese_variants(payload, iso_only=True) if encoding == "utf-8" and b"\x1b$" in payload else []
    try:
        if not variants:
            variants = [(encoding, payload.decode(encoding))]
    except UnicodeError:
        if declared_codec:
            try:
                variants = [(declared_codec, payload.decode(declared_codec))]
            except UnicodeError:
                variants = []
        else:
            variants = _japanese_variants(payload) if encoding == "utf-8" and not BINARY_CONTROL.search(payload[:PROBE_BYTES]) else []
    if not variants:
        reason = "TEXT_UNREADABLE_UnicodeDecodeError"
        if (encoding == "utf-8" and not keymap and not _instruction_path(name)
                and Path(name).suffix.casefold() not in NON_BINARY_DOCUMENT_SUFFIXES
                and BINARY_CONTROL.search(payload[:PROBE_BYTES])):
            reason = "OPAQUE_BINARY_UNINSPECTED"
        _unknown(report, reason, entry)
        return
    if variants[0][0] != encoding:
        entry["text_encodings"] = [codec for codec, _ in variants]
    for _, text in variants:
        logical = text.translate(LINE_SEPARATORS) if not text.isascii() or "\f" in text else text
        findings_before = len(report["findings"])
        completed = _scan(report, entry, name, text, logical, deadline)
        remaining = CHARACTER_EVIDENCE_LIMIT - sum(len(item.get("character_warnings", ()))
                                                  for item in report["unknown_conditions"])
        escapes = _vim_literal_escape_offsets(text) if keymap and "\x16" in text else ()
        details, count, review_complete = _character_warnings(
            text, logical, report["findings"][findings_before:], remaining, deadline, escapes)
        if count:
            condition = _unknown(report, "TEXT_CONTROL_OR_FORMAT_CHARACTER", entry)
            if condition is not None:
                _character_evidence(entry, condition, details, count, review_complete)
                if (completed and len(variants) == 1 and review_complete and len(details) == count
                        and all(warning["codepoint"] == "U+0008" for warning in details)):
                    condition["instruction_scan_completed"] = True
            return
        if completed and not review_complete:
            _unknown(report, "TEXT_DEADLINE", entry)
            return
        if not completed:
            return
    entry["text_status"] = "READ_TEXT"
    report["coverage"]["text_files_read"] += 1
    report["coverage"]["text_bytes_read"] += size
    report["_checked_documents"].add(entry["index"])


def _detector_constants(tree):
    """Recognize exact rule, trigger, and license-comparison constants in assignments."""
    for stmt in ast.walk(tree):
        if (not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1
                or not isinstance(stmt.targets[0], ast.Name)):
            continue
        name, value = stmt.targets[0].id, stmt.value
        if (name in ("ZLIB_LICENSE_HEADER", "legal") and isinstance(value, ast.Constant)
                and value.value == ZLIB_LICENSE_HEADER):
            yield "AUTHORITY_SPOOFING", value
        if name == "RULES":
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "tuple"
                    and len(value.args) == 1 and not value.keywords and isinstance(value.args[0], ast.GeneratorExp)
                    and len(value.args[0].generators) == 1):
                value = value.args[0].generators[0].iter
            if isinstance(value, (ast.Tuple, ast.List)):
                for row in value.elts:
                    if not isinstance(row, ast.Tuple) or len(row.elts) != 2:
                        continue
                    label, pattern = row.elts
                    if (isinstance(label, ast.Constant) and isinstance(label.value, str)
                            and isinstance(pattern, ast.Constant) and isinstance(pattern.value, str)
                            and pattern.value in DETECTOR_DEFINITION_LITERALS.get(label.value, ())):
                        yield label.value, pattern
        elif name == "ASCII_TRIGGERS" and isinstance(value, ast.Dict):
            for label, terms in zip(value.keys, value.values):
                if (isinstance(label, ast.Constant) and isinstance(label.value, str)
                        and isinstance(terms, ast.Tuple) and all(isinstance(term, ast.Constant) for term in terms.elts)
                        and tuple(term.value for term in terms.elts) == ASCII_TRIGGERS.get(label.value)):
                    for term in terms.elts:
                        yield label.value, term


def _detector_literal_spans(name, source, deadline):
    if (not name.endswith(".py") or len(source) > DETECTOR_LITERAL_MAX_BYTES
            or not any(marker in source for marker in ("RULES", "ASCII_TRIGGERS", ZLIB_LICENSE_HEADER[:64]))
            or len(source.encode("utf-8")) > DETECTOR_LITERAL_MAX_BYTES
            or "\r" in source.replace("\r\n", "\n") or time.monotonic() >= deadline):
        return {}
    try:
        # Parsing archive text must not send its lines to the worker diagnostics pipe.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(source)
        constants = tuple(_detector_constants(tree))
        if not constants or time.monotonic() >= deadline:
            return {}
        lines = source.split("\n")
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line) + 1)
        # AST columns count UTF-8 bytes. Token columns count Unicode characters.
        def ast_offset(row, byte_column):
            return offsets[row - 1] + len(lines[row - 1].encode("utf-8")[:byte_column].decode("utf-8"))

        strings = [(offsets[tok.start[0] - 1] + tok.start[1], offsets[tok.end[0] - 1] + tok.end[1])
                   for tok in tokenize.generate_tokens(io.StringIO(source).readline) if tok.type == tokenize.STRING]
    except (SyntaxError, ValueError, RecursionError, OverflowError, tokenize.TokenError):
        return {}
    if time.monotonic() >= deadline:
        return {}
    starts = [start for start, _ in strings]
    spans = {}
    for category, node in constants:
        left = ast_offset(node.lineno, node.col_offset)
        right = ast_offset(node.end_lineno, node.end_col_offset)
        # An AST constant can span adjacent tokens and intervening comments.
        for span in strings[bisect_left(starts, left):bisect_left(starts, right)]:
            if span[1] <= right:
                spans.setdefault(category, []).append(span)
    return spans


def _class_role_field_spans(name, source, deadline):
    """Pin the matched prefix to a trivial class-field declaration in real Python."""
    if (not name.endswith(".py") or len(source) > ROLE_FIELD_MAX_BYTES
            or source.count("\n") >= ROLE_FIELD_MAX_LINES):
        return set()
    candidates = {source.count("\n", 0, row.start()) + 1: row
                  for row in ROLE_FIELD_ROW.finditer(source)}
    if (not candidates or len(source.encode("utf-8")) > ROLE_FIELD_MAX_BYTES
            or "\r" in source.replace("\r\n", "\n") or time.monotonic() >= deadline):
        return set()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, OverflowError):
        return set()
    if time.monotonic() >= deadline:
        return set()
    accepted = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.AnnAssign):
                continue
            row = candidates.get(stmt.lineno)
            if (row is not None and stmt.end_lineno == stmt.lineno and stmt.simple
                    and isinstance(stmt.target, ast.Name) and stmt.target.id == row["name"]
                    and stmt.target.col_offset == row.start("name") - row.start()
                    and isinstance(stmt.annotation, ast.Name) and stmt.annotation.id in ROLE_FIELD_TYPES
                    and (stmt.value is None or isinstance(stmt.value, ast.Constant) and (
                        stmt.value.value is None or (stmt.annotation.id == "bool" and type(stmt.value.value) is bool)))):
                accepted.add(row.span("role"))
    return accepted


RUST_TYPED_FIELD = re.compile(
    r"[A-Za-z_]\w*\s*:\s*(?:&(?:'\w+\s+)?(?:mut\s+)?)?[A-Z]\w*(?:<[\w'<>, &]+>)?,")
RUST_DECLARATION = re.compile(
    r"(?:(?:pub(?:\([^()]+\))?\s+)?struct\s+[A-Za-z_]\w*(?:<[^<>]+>)?\s*\{|"
    r"(?:pub(?:\([^()]+\))?\s+)?fn\s+[A-Za-z_]\w*(?:<[^<>]+>)?\s*\()")


def _is_code_or_license_context(path, source, category, start, end):
    if category not in {"ROLE_SPOOFING", "AUTHORITY_SPOOFING"}:
        return False
    left = source.rfind("\n", max(0, start - 256), start) + 1
    right = source.find("\n", end, min(len(source), end + 256))
    if right < 0:
        return False
    line = source[left:right].strip()
    if category == "AUTHORITY_SPOOFING" and path.endswith(".py") and start < 2048:
        return source.startswith(ZLIB_LICENSE_HEADER, left) and "authors be held liable" in source[max(0, left - 240):left]
    if category != "ROLE_SPOOFING" or not path.endswith(".rs") or not RUST_TYPED_FIELD.fullmatch(line):
        return False
    # Only an immediately surrounding Rust declaration and type-only rows
    # qualify. Role labels carrying natural-language instructions still scan.
    for previous in reversed(source[max(0, left - 768):left].splitlines()[-8:]):
        row = previous.strip()
        if RUST_DECLARATION.fullmatch(row):
            return True
        if row and not row.startswith("//") and not RUST_TYPED_FIELD.fullmatch(row):
            return False
    return False


def _is_help_or_syntax_context(path, source, category, start, end):
    original = source[start:end]
    if category == "ROLE_SPOOFING" and original.casefold() == "system:":
        if _instruction_path(path):
            return False
        pattern = WRAPPED_HELP_DESCRIPTION
    elif category == "DATA_TRANSMISSION_REQUEST" and VIM_POST_KEYWORD_LIST.fullmatch(original):
        pattern = VIM_REGION_PATTERN
    else:
        return False
    line = source.rfind("\n", max(0, start - 1024), start) + 1
    previous = source.rfind("\n", max(0, line - 224), line - 1) + 1
    if line == 0 or line - previous > 224:
        return False
    limit = min(len(source), end + 1024)
    right = source.find("\n", end, limit)
    if right < 0 and limit != len(source):
        return False
    if (context := pattern.fullmatch(source, previous, right if right >= 0 else limit)) is None:
        return False
    if category == "ROLE_SPOOFING":
        return context.span("label") == (start, end) and not AGENT_CONTEXT.search(
            source, max(0, previous - 160), min(len(source), context.end() + 160))
    return context.start("pattern") <= start < end <= context.end("pattern")


def _python_transmission_operand_bounds(name, source, deadline):
    """Recognize syntax tokens, while leaving comments and string contents in the scan."""
    if (not name.endswith(".py") or len(source) > DETECTOR_LITERAL_MAX_BYTES
            or not (".post(" in source and ("TestClient" in source or "@" in source)
                    or "@example.com" in source and "email" in source)
            or time.monotonic() >= deadline):
        return {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(source)
            nodes = tuple(ast.walk(tree))
    except (SyntaxError, ValueError, RecursionError, OverflowError):
        return {}
    if time.monotonic() >= deadline:
        return {}

    imports = {alias.asname or alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
               and node.level == 0 and node.module in {"fastapi.testclient", "starlette.testclient"}
               for alias in node.names if alias.name == "TestClient"}
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    frames = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)

    def frame(node):
        current = parents.get(node, tree)
        while not isinstance(current, frames):
            current = parents[current]
        return current

    writes = Counter((frame(node), node.id) for node in nodes
                     if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)))
    shadowed = {(frame(node), node.arg) for node in nodes if isinstance(node, ast.arg)}
    shadowed.update((frame(node), node.name) for node in nodes
                    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)))
    changed_receivers = {(frame(node), node.value.id) for node in nodes
                         if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del))
                         and isinstance(node.value, ast.Name)}
    names_written = {name for _, name in writes.keys() | shadowed}
    import_counts = Counter((alias.asname or alias.name).split(".")[0] for node in nodes
                            if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names)
    constructors = {name for name in imports - names_written if import_counts[name] == 1}
    typed_clients = {(frame(node), node.arg) for node in nodes if isinstance(node, ast.arg)
                     and isinstance(node.annotation, ast.Name) and node.annotation.id in constructors}
    shared_bindings = {name for node in nodes if isinstance(node, (ast.Global, ast.Nonlocal)) for name in node.names}
    modified_names = {name for _, name in changed_receivers} | shared_bindings
    pytest_imported = (import_counts["pytest"] == 1 and "pytest" not in names_written
                       and any(isinstance(node, ast.Import) and any(alias.name == "pytest" and not alias.asname
                                                                  for alias in node.names) for node in tree.body))

    def in_process(node):
        return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in constructors
                and len(node.args) == 1 and not isinstance(node.args[0], ast.Starred) and not node.keywords)

    clients = Counter()
    for node in nodes:
        if isinstance(node, ast.Assign) and in_process(node.value):
            clients.update((frame(target), target.id) for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name) and in_process(node.context_expr):
            clients[frame(node), node.optional_vars.id] += 1

    def admitted_binding(key):
        return (key not in shadowed and key[1] not in modified_names and clients[key] > 0
                and writes[key] == clients[key])

    def qualified(call, dotted_name):
        if not isinstance(call, ast.Call):
            return False
        value = call.func
        for part in reversed(dotted_name[1:]):
            if not isinstance(value, ast.Attribute) or value.attr != part:
                return False
            value = value.value
        return isinstance(value, ast.Name) and value.id == dotted_name[0]

    fixtures = set()
    route_arguments = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        returns = [child.value for child in ast.walk(node) if isinstance(child, ast.Return) and frame(child) is node]
        for decorator in node.decorator_list:
            if not pytest_imported:
                break
            if qualified(decorator, ("pytest", "fixture")) and returns and all(
                    in_process(value) or isinstance(value, ast.Name) and admitted_binding((node, value.id)) for value in returns):
                name = next((kw.value for kw in decorator.keywords if kw.arg == "name"), ast.Constant(node.name))
                if isinstance(name, ast.Constant) and isinstance(name.value, str):
                    fixtures.add(name.value)
            if (qualified(decorator, ("pytest", "mark", "parametrize")) and len(decorator.args) == 2
                    and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str)
                    and isinstance(decorator.args[1], (ast.List, ast.Tuple)) and decorator.args[1].elts
                    and all(isinstance(item, ast.Constant) and isinstance(item.value, str) and RELATIVE_POST_PATH.fullmatch(item.value)
                        for item in decorator.args[1].elts)):
                route_arguments.add((node, decorator.args[0].value))

    decorator_calls = {node for definition in nodes if isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef))
                       for node in definition.decorator_list if isinstance(node, ast.Call)}
    lines, starts = source.split("\n"), [0]
    for line in lines:
        starts.append(starts[-1] + len(line) + 1)

    def offset(line, column):
        return starts[line - 1] + len(lines[line - 1].encode("utf-8")[:column].decode("utf-8"))

    def end_offset(node):
        return offset(node.end_lineno, node.end_col_offset)

    result = {}
    for node in nodes:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "post" and node.args:
            scope = frame(node)
            route = node.args[0]
            literal_route = isinstance(route, ast.Constant) and isinstance(route.value, str) and RELATIVE_POST_PATH.fullmatch(route.value)
            parameterized_route = (isinstance(route, ast.Name) and (scope, route.id) in route_arguments
                                   and (scope, route.id) in shadowed and not writes[scope, route.id])
            if not literal_route and not parameterized_route:
                continue
            receiver = node.func.value
            local = in_process(receiver)
            typed_route = False
            if isinstance(receiver, ast.Name):
                key = (scope, receiver.id)
                typed_route = literal_route and key in typed_clients and not writes[key] and receiver.id not in modified_names
                local = admitted_binding(key)
                if not local and not writes[key] and receiver.id not in modified_names:
                    local = (admitted_binding((tree, receiver.id)) if key not in shadowed else
                             isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and scope.name.startswith("test_")
                             and receiver.id in fixtures)
            token = end_offset(node.func) - len(node.func.attr)
            if local or typed_route or literal_route and node in decorator_calls:
                result[token] = end_offset(node if local else node.args[0])
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and key.value == "email"
                        and isinstance(value, ast.Constant) and isinstance(value.value, str)
                        and re.fullmatch(r"[A-Za-z0-9_.+-]+@example\.com", value.value)):
                    opening = offset(key.lineno, key.col_offset)
                    if source[opening:opening + 7] in ("\"email\"", "'email'"):
                        result[opening + 1] = end_offset(node)
    return result


def _is_transmission_label_context(path, source, start, end):
    previous_line = source.rfind("\n", max(0, start - 512), start)
    next_line = source.find("\n", end, end + 512)
    if previous_line < 0 and start >= 512 or next_line < 0 and end + 512 < len(source):
        return False
    left = previous_line + 1
    line = source[left:next_line if next_line >= 0 else len(source)]
    if path.endswith((".yaml", ".yml")) and (row := WORKFLOW_EMAIL_FIELD.fullmatch(line)):
        return row.start("label") + left == start and end <= left + row.end()
    prefix = source[max(left, start - 160):start]
    if (re.search(r"(?:^|\s)blog[ \t]+$", prefix, re.IGNORECASE) and source[start:start + 4].casefold() == "post"
            and re.match(r"(?:\)|[ \t]+edit\b)", source[start + 4:start + 14])):
        return True
    if (CONFIGURATION_ENUMERATION.search(prefix) and CONFIGURATION_EMAIL_KIND.match(source, start)
            and not AGENT_CONTEXT.search(line)
            and re.search(r"\b(?:configurations?|environment variables)\b|konfigürasyon|आदि", line, re.IGNORECASE)
            and re.search(r"\b(?:send|upload|transmit|post|must|should)\b|https?://", line, re.IGNORECASE) is None):
        return True
    if TOKEN_REQUEST_RESPONSE.fullmatch(line.strip()):
        return True
    if ("`OAuth2PasswordBearer`" in line and "`tokenUrl`" in line and AGENT_CONTEXT.search(line) is None
            and re.search(r"https?://", line, re.IGNORECASE) is None):
        if TOKEN_ENDPOINT_CREDENTIAL_FIELDS.fullmatch(source, start, end):
            return True
        if (source.startswith("トークンを取得するために`username`と`password`を"
                              "送信", start)
                and line.rstrip("\r").endswith("するURLを指定します。")):
            return True
    before_clause, subject, description = line.partition("they will ")
    if ("when the clients" in before_clause and subject and start == left + len(before_clause) + len(subject)
            and AGENT_CONTEXT.search(line) is None and CLIENT_FIELD_DESCRIPTION.fullmatch(subject + description.rstrip("\r"))):
        return True
    # A list of example form fields with a reserved address and a literal
    # placeholder is explanatory. Other values and any later requests scan.
    if "@example.com`" in line and "`token=secret`" in line:
        fields = list(FORM_EXAMPLE_FIELD.finditer(line))
        values = {field[1]: field[2] for field in fields}
        if (len(values) == len(fields) and set(values) == FORM_EXAMPLE_KEYS
                and values["contact_type"] in {"person", "organization"}
                and re.fullmatch(r"[A-Za-z][A-Za-z_0-9-]{0,32}", values["name"])
                and values["token"] == "secret"
                and re.fullmatch(r"[A-Za-z0-9_.+-]+@example\.com", values.get("email", ""))
                and values["notification_type"] == "email"
                and all(FORM_EXAMPLE_SEPARATOR.fullmatch(line[a.end():b.start()]) for a, b in zip(fields, fields[1:]))):
            first, last = left + fields[0].start(), left + fields[-1].end()
            return end <= last and (first <= start or source[start:first].casefold().strip() == "send")
    if source[end - 2:end] == "送信":
        if AGENT_CONTEXT.search(line) is not None:
            return False
        if source.startswith("するなど", end) and re.search(r"フォームの送信時に[ \t]+(?:CSRF|XSRF)[ \t]*$", prefix):
            return True
        if OTLP_PROVIDER_DESCRIPTION.fullmatch(line[start - left:].rstrip("\r")):
            return True
        if re.fullmatch(r"(?:\*[ \t]+)?(?:したがって、)?APIで認証するため、HTTPヘッダー`Authorization`に"
                        r"`Bearer *`の文字列とトークンを加えた値を"
                        r"送信します。", line.strip()):
            return True
        if re.fullmatch(r"開発者ツールを開くと、送信されるデータにはトークンだけが含まれており、パスワードは"
                        r"ユーザーを認証してアクセストークンを取得する最初のリクエストでのみ"
                        r"送信され、"
                        r"その後は送信されないことがわかります：", line.strip()):
            return True
    return False


def _is_japanese_override_description(text, start, end):
    if JA_OVERRIDE_NON_DIRECTIVE.match(text, end):
        return True
    # A marked example or an explicit description can quote a directive.
    # Bare quotes and text that asks the reader to follow them remain in scope.
    prefix_start = max(0, start - 128)
    prefix = text[prefix_start:start]
    before = prefix.rsplit("\n", 1)[-1].rstrip(" \t　")
    if not before or before[-1] not in "「『":
        return False
    tail = text[end:end + 192].split("\n", 1)[0]
    if len(tail) == 192 and end + 192 < len(text):
        return False
    closing = "」" if before[-1] == "「" else "』"
    _, found, after = tail.partition(closing)
    labelled = (prefix_start == 0 or "\n" in prefix) and JA_OVERRIDE_QUOTE_LABEL.search(before[:-1])
    return bool(found and (JA_OVERRIDE_QUOTE_TAIL.fullmatch(after) or (labelled and not after.strip(" \t　。．\r"))))


def _is_descriptive_match(category, text, match):
    """Disambiguate the matched clause without exempting its file or neighboring text."""
    start, end = match.span()
    if category == "INSTRUCTION_OVERRIDE" and match[0].endswith(("無視", "上書き")):
        return _is_japanese_override_description(text, start, end)
    if category == "AUTHORITY_SPOOFING":
        prefix = text[max(0, start - 100):start]
        if CONTRACT_AUTHORITY_PHRASE.search(prefix):
            citation = CONTRACT_AUTHORITY_CITATION.match(text, end, end + 120)
            return (citation is not None and citation["party"].casefold() != "agent"
                    and AGENT_GRANTEE.search(citation["party"]) is None)
    elif category == "DATA_TRANSMISSION_REQUEST":
        if match[0].endswith(("送信", "アップロード", "外部へ")):
            return JA_TRANSMISSION_PROHIBITION.match(text, end, end + 40) is not None
        prefix = text[max(0, start - 80):start]
        verb_end = start + len(match[0].split(maxsplit=1)[0])
        fields = EMAIL_FIELD_LIST.match(text, start, start + 150)
        return (TRANSMISSION_PROHIBITION.search(prefix) is not None
                or TRANSMISSION_OBJECT_PROHIBITION.match(text, verb_end, end) is not None
                or TRANSMISSION_NOT_DESCRIBED.search(prefix) is not None
                or TRANSMISSION_NOT_REQUIRED.search(prefix) is not None
                or (fields is not None and TRANSMISSION_CLAUSE_QUALIFIER.search(fields[0]) is None)
                or (TRANSMISSION_REMAINING_CASES.search(prefix) is not None
                    and TRANSMISSION_OR_NOTHING.match(text, end) is not None)
                or (start > 0 and HTTP_METHOD_ARGUMENTS.match(text, start - 1, end + 12) is not None))
    elif category == "ROLE_SPOOFING":
        return JA_ROLE_ATTRIBUTION.fullmatch(match[0]) is not None and JA_ROLE_NOUN.match(text, end) is not None
    elif category == "TOOL_EXECUTION_REQUEST":
        return match[0].endswith(("実行", "呼び出し")) and JA_OPERATION_NOUN.match(text, end) is not None
    return False


def _scan_variant(report, entry, source, logical, text, removed, seen, role_fields, detector_literals,
                  transmission_operands, deadline):
    ascii_lower = text.lower() if text.isascii() else None
    direct = False
    for category, pattern in RULES:
        if time.monotonic() >= deadline:
            _unknown(report, "TEXT_DEADLINE", entry)
            return False
        if ascii_lower is not None and not any(term in ascii_lower for term in ASCII_TRIGGERS[category]):
            continue
        position = 0
        while match := pattern.search(text, position):
            position = match.end()
            if time.monotonic() >= deadline:
                _unknown(report, "TEXT_DEADLINE", entry)
                return False
            if category in CONTEXTUAL and not direct and not AGENT_CONTEXT.search(
                text, max(0, match.start() - 160), min(len(text), match.end() + 160)
            ):
                continue
            start, end = match.span()
            if removed:
                start += bisect_right(removed, start)
                end += bisect_left(removed, end)
            if _is_code_or_license_context(entry["path"], source, category, start, end):
                continue
            if any(left <= start < end <= right for left, right in detector_literals.get(category, ())):
                continue
            if (_is_descriptive_match(category, text, match)
                    or _is_help_or_syntax_context(entry["path"], source, category, start, end)
                    or (category == "DATA_TRANSMISSION_REQUEST" and (end <= transmission_operands.get(start, -1)
                        or _is_transmission_label_context(entry["path"], source, start, end)))):
                if category == "DATA_TRANSMISSION_REQUEST":
                    # A broad candidate can span a prohibition and a later request.
                    # Check other verb starts before discarding this candidate.
                    position = match.start() + 1
                continue
            if category == "ROLE_SPOOFING" and (start, end) in role_fields:
                continue
            if category in ("INSTRUCTION_OVERRIDE", "ROLE_SPOOFING", "AUTHORITY_SPOOFING"):
                direct = True
            identity = (category, start, end)
            if identity in seen:
                continue
            seen.add(identity)
            if len(report["findings"]) >= report.get("_finding_limit", LIMITS["findings"]):
                if report.get("_thorough"):
                    report["finding_details_truncated"] = True
                    continue
                _unknown(report, "FINDING_LIMIT", entry)
                return False
            report["findings"].append({
                "category": category, "entry_index": entry["index"], "path": entry["path"],
                "line": logical.count("\n", 0, start) + 1, "start_char": start, "end_char": end,
                "matched_text": source[start:min(end, start + LIMITS["evidence_chars"])],
                "source_role": "UNTRUSTED_ARCHIVE_DATA",
            })
    if time.monotonic() < deadline:
        return True
    _unknown(report, "TEXT_DEADLINE", entry)
    return False


def _scan(report, entry, name, source, logical, deadline):
    seen = set()
    role_fields = _class_role_field_spans(name, source, deadline)
    detector_literals = _detector_literal_spans(name, source, deadline)
    transmission_operands = _python_transmission_operand_bounds(name, source, deadline)
    if logical.isascii() or not SCAN_MARK_PATTERN.search(logical):
        return _scan_variant(report, entry, source, logical, logical, (), seen, role_fields, detector_literals,
                             transmission_operands, deadline)
    # Check blank and omitted presentation data while retaining source offsets.
    # All other text (including malformed citation lookalikes) stays in the scan.
    # A well-formed reference contains only structural identifier fields.
    blanked = FILE_CITATION.sub(lambda m: " " * len(m[0]), logical) if "\ue200" in logical else logical
    spaces = blanked.translate(SCAN_MARK_SPACES)
    if not _scan_variant(report, entry, source, logical, spaces,
                         (), seen, role_fields, detector_literals, transmission_operands, deadline):
        return False
    removed = array("I", (match.start() - i for i, match in enumerate(SCAN_MARK_PATTERN.finditer(logical))))
    return _scan_variant(report, entry, source, logical, logical.translate(SCAN_MARK_REMOVAL),
                         removed, seen, role_fields, detector_literals, transmission_operands, deadline)


def _new_report(limits=LIMITS):
    report = {
        "format": REPORT_FORMAT,
        "limits": dict(limits),
        "input": {}, "entries": [], "findings": [], "unknown_conditions": [],
        "_reasons": Counter(), "_archive_reasons": Counter(), "_nested": [], "_inner_instruction_items": {},
        "_checked_documents": set(), "_inner_checked_documents": [],
        "coverage": {"listed_entries": 0, "text_files_read": 0, "text_bytes_read": 0,
                     "hash_only_files": 0, "uninspected_files": 0, "directories": 0},
        "safety_proven": False,
        "authorizes_actions": False,
        "scope": ("Outer ZIP structure, direct-member SHA, and selected plain text in "
                  "supported ZIP/WHL, TAR, and GZIP within profile limits."),
        "limitations": [
            "NOT_DETECTED is not proof of safety or absence of prompt injection.",
            "Fixed English/Japanese heuristics can miss obfuscation and other languages and can flag quotations.",
            "Inner member SHA is used only for integrity. The threat database check covers outer members.",
            "Recognized unsupported formats and unread applicable members have separate dispositions and reasons.",
            "Binary assets are SHA-checked; their internal content and metadata are outside the instruction scan.",
            "No malware, execution, OS isolation, VM or AI-model resistance claim.",
        ],
    }
    return report


def inspect_zip(path: str | os.PathLike | int) -> dict:
    """Read one regular ZIP snapshot; return finite JSON-compatible evidence.

    Path input is opened read-only without following a symlink. An integer input
    is an already-open regular-file or pipe FD, duplicated before reading. The
    caller retains the original FD. A pipe writer must close its end and the
    worker caller must enforce a deadline. No member is written to disk,
    imported, executed or sent anywhere.
    """
    report = _new_report()
    try:
        from_fd = isinstance(path, int)
        fd = os.dup(path) if from_fd else os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            regular = stat.S_ISREG(before.st_mode)
            if not regular and not (from_fd and stat.S_ISFIFO(before.st_mode)):
                _unknown(report, "INPUT_NOT_REGULAR_FILE")
                return _finish(report)
            if regular and before.st_size > LIMITS["archive_bytes"]:
                _unknown(report, "ARCHIVE_SIZE_LIMIT")
                return _finish(report)
            data = source.read(LIMITS["archive_bytes"] + 1)
            after = os.fstat(source.fileno())
        report["input"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if len(data) > LIMITS["archive_bytes"]:
            _unknown(report, "ARCHIVE_SIZE_LIMIT")
            return _finish(report)
        if regular and (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            _unknown(report, "INPUT_CHANGED_DURING_READ")
            return _finish(report)
    except (OSError, ValueError) as exc:
        _unknown(report, "INPUT_UNREADABLE_" + type(exc).__name__)
        return _finish(report)

    return inspect_snapshot(data, report)


def inspect_snapshot(data: bytes, report=None, *, deadline=None, thorough=False, on_resolved=None) -> dict:
    """Inspect without extracting. Thorough limits are selected only by the caller."""
    deadline = time.monotonic() + (THOROUGH_SECONDS if thorough else DEADLINE_SECONDS) if deadline is None else deadline
    budget = _Budget(deadline, thorough, on_resolved)
    if report is None:
        report = _new_report(budget.limits)
        report["input"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if len(data) > LIMITS["archive_bytes"]:
            _unknown(report, "ARCHIVE_SIZE_LIMIT")
            return _finish(report)
    if thorough:
        report["inspection_profile"] = "THOROUGH"
        report["_thorough"] = True
    _inspect_level(data, report, budget)
    return _finish(report)


def _nested_summary(report, entry, kind, status, reasons, child=None):
    coverage = child["coverage"] if child else {}
    summary = child["scope_detail"] if child else {}
    descendants = summary.get("nested", [])
    report["_nested"].append({
        "entry_index": entry["index"], "kind": kind, "status": status,
        "entries": coverage.get("listed_entries", 0) + sum(row["entries"] for row in descendants),
        "text_files_read": coverage.get("text_files_read", 0) + sum(row["text_files_read"] for row in descendants),
        "text_bytes_read": coverage.get("text_bytes_read", 0) + sum(row["text_bytes_read"] for row in descendants),
        "ordinary_out_of_scope": summary.get("ordinary_out_of_scope", 0)
                                 + sum(row["ordinary_out_of_scope"] for row in descendants),
        "child_report": child is not None,
        "reasons": reasons,
    })


def _merge_archive(report, entry, kind, child):
    """Flatten descendants into the outer member's bounded receipt namespace."""
    scope = child["instruction_scope"]
    offsets = {}
    cursor = child["coverage"]["listed_entries"]
    for row in child["scope_detail"]["nested"]:
        offsets[row["entry_index"]] = cursor
        cursor += row["entries"]

    def project(row):
        index = row["entry_index"]
        parts = [child["entries"][index]["path"]]
        nested_index = row.get("nested_entry_index")
        if nested_index is not None:
            index = offsets[index] + nested_index
            parts.append(row["nested_member_path"])
        return {**row, "entry_index": entry["index"], "nested_entry_index": index,
                "nested_member_path": _display_path(" / ".join(parts))}

    items = [project(item) for item in scope["items"]]
    if scope["archive_reasons"]:
        items.append({"entry_index": entry["index"], "disposition": "UNREAD", "reasons": scope["archive_reasons"]})
    report["_inner_instruction_items"][entry["index"]] = items
    report["_inner_checked_documents"].extend(project(member) for member in scope["checked_members"])
    for finding in child["findings"]:
        tail = " / ".join(part for part in (finding["path"], finding.get("nested_member_path")) if part)
        report["findings"].append({**finding, "entry_index": entry["index"], "path": entry["path"],
                                  "nested_member_path": _display_path(tail)})
    if child.get("finding_details_truncated"):
        report["finding_details_truncated"] = True

    reasons = Counter()
    for item in items:
        reasons.update({key: count for key, count in item["reasons"].items()
                        if key not in {"TEXT_BODY_NOT_APPLICABLE", "INTERNAL_LINK_REFERENCE"}})
    if reasons:
        _unknown(report, "NESTED_CONTENT_UNRESOLVED", entry)
    else:
        entry["text_status"] = "SHA_ONLY"
        report["coverage"]["hash_only_files"] += 1
    status = "COMPLETE" if not reasons else "PARTIAL" if cursor else "UNREAD"
    _nested_summary(report, entry, kind, status, dict(reasons), child)


def _archive_kind(suffix, payload):
    if suffix in NESTED_ZIP_SUFFIXES:
        return "WHEEL" if suffix == ".whl" else "ZIP"
    if suffix in {".gz", ".tgz"} or payload.startswith(b"\x1f\x8b"):
        return "GZIP"
    if suffix == ".tar" or payload[257:262] == b"ustar":
        return "TAR"
    if (not suffix or suffix in NON_BINARY_DOCUMENT_SUFFIXES) and payload.startswith(ZIP_HEADERS):
        return "ZIP"
    if payload.startswith(CONTAINER_HEADERS):
        return "OTHER_ARCHIVE"
    return "CANDIDATE"


def _read_archive_member(report, entry, suffix, payload, budget, depth):
    kind = _archive_kind(suffix, payload)
    if kind == "OTHER_ARCHIVE":
        reason = "UNSUPPORTED_ARCHIVE_BODY_OUT_OF_SCOPE"
    elif kind == "CANDIDATE":
        reason = "NESTED_FORMAT_UNSUPPORTED"
    elif kind in {"ZIP", "WHEEL"} and not payload.startswith(ZIP_HEADERS):
        reason = "NESTED_FORMAT_UNSUPPORTED"
    elif depth >= budget.depth:
        reason = "NESTED_DEPTH_LIMIT"
    elif entry["uncompressed_bytes"] > budget.limits["text_bytes_each"]:
        reason = "NESTED_ARCHIVE_SIZE_LIMIT"
    else:
        reason = None
    if reason:
        _unknown(report, reason, entry)
        _nested_summary(report, entry, kind, "UNREAD", {reason: 1})
        return
    child = _new_report(budget.limits)
    child["input"] = {"bytes": len(payload), "sha256": entry["verified_sha256"]}
    child["_finding_limit"] = report.get("_finding_limit", LIMITS["findings"]) - len(report["findings"])
    child["_thorough"] = budget.depth > 1
    ratio = budget.limits["expansion_ratio"] * max(1, entry["compressed_bytes"])
    budget.ancestors.append(entry["index"])
    try:
        if kind in {"ZIP", "WHEEL"}:
            _inspect_level(bytes(payload), child, budget, depth=depth + 1, inner_ratio_cap=ratio)
        elif kind == "TAR":
            _inspect_tar(bytes(payload), child, budget, depth + 1, ratio)
        else:
            _inspect_gzip(bytes(payload), child, budget, depth + 1, ratio, entry["path"])
    finally:
        budget.ancestors.pop()
    finished = _finish(child)
    _merge_archive(report, entry, kind, finished)
    if budget.on_resolved is not None:
        scope = finished["instruction_scope"]
        covered = not scope["archive_reasons"] and all(item["disposition"] != "UNREAD" for item in scope["items"])
        if covered:
            budget.resolved(entry, covered=True)


def _validate_member_path(report, name, entry, seen):
    if len(name.encode("utf-8", errors="replace")) > LIMITS["path_bytes"]:
        _unknown(report, "PATH_SIZE_LIMIT", entry)
    parts = name.rstrip("/").split("/")
    if (not name or name.startswith("/") or ntpath.splitdrive(name)[0] or "\\" in name
            or any(part in {"", ".", ".."} for part in parts)
            or any(unicodedata.category(c).startswith("C") for c in name)):
        _unknown(report, "UNSAFE_OR_AMBIGUOUS_PATH", entry)
    identity = unicodedata.normalize("NFC", name.rstrip("/")).casefold()
    if identity in seen:
        _unknown(report, "DUPLICATE_OR_COLLIDING_PATH", entry)
    seen.add(identity)


def _stream_entry(report, name, size, directory=False):
    row = {"index": len(report["entries"]), "path": _display_path(name),
           "compressed_bytes": size, "uncompressed_bytes": size, "expansion_ratio": 1.0,
           "compression_method": 0, "encrypted": False, "directory": directory,
           "issues": [], "text_status": "UNINSPECTABLE", "read_budget_reserved": 0}
    report["entries"].append(row)
    return row


def _consume_stream_entry(report, entry, name, data, budget, depth):
    size = len(data)
    if time.monotonic() >= budget.deadline:
        _unknown(report, "MEMBER_DEADLINE", entry)
    elif size > budget.member_bytes:
        _unknown(report, "MEMBER_READ_BUDGET_LIMIT", entry)
    else:
        budget.member_bytes -= size
        entry["read_budget_reserved"] = size
        entry["verified_sha256"] = hashlib.sha256(data).hexdigest()
        suffix = Path(name).suffix.casefold()
        cap = budget.limits["text_bytes_each"]
        if (suffix in NESTED_SUFFIXES | NESTED_ZIP_SUFFIXES | NESTED_STREAM_SUFFIXES
                or data.startswith(CONTAINER_HEADERS) or data[257:262] == b"ustar"):
            _read_archive_member(report, entry, suffix, data if size <= cap else data[:PROBE_BYTES], budget, depth)
        else:
            _read_text(report, entry, name, data if size <= cap else data[:PROBE_BYTES], size, budget)
    if entry["text_status"] == "UNINSPECTABLE":
        report["coverage"]["uninspected_files"] += 1
    budget.resolved(entry)


def _inspect_gzip(data, report, budget, depth, ratio_cap, outer_name):
    if not data.startswith(b"\x1f\x8b"):
        _unknown(report, "GZIP_STRUCTURE_HEADER_INVALID")
        return
    ratio_cap = min(ratio_cap, LIMITS["expansion_ratio"] * len(data))
    limit = min(ratio_cap, budget.limits["member_bytes"], budget.member_bytes)
    output = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as source:
            while True:
                if time.monotonic() >= budget.deadline:
                    _unknown(report, "MEMBER_DEADLINE")
                    return
                chunk = source.read(min(CHUNK_BYTES, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit:
                    reason = ("NESTED_EXPANSION_RATIO_LIMIT" if limit == ratio_cap else
                              "MEMBER_SIZE_LIMIT" if limit == budget.limits["member_bytes"] else "MEMBER_READ_BUDGET_LIMIT")
                    _unknown(report, reason)
                    return
    except (OSError, EOFError, zlib.error):
        _unknown(report, "GZIP_STRUCTURE_STREAM_INVALID")
        return
    expanded = bytes(output)
    name = outer_name.rsplit("/", 1)[-1]
    if name.casefold().endswith(".tgz") or name.casefold().endswith(".tar.gz") or expanded[257:262] == b"ustar":
        budget.member_bytes -= len(expanded)
        _inspect_tar(expanded, report, budget, depth, ratio_cap)
        return
    if budget.entries < 1:
        _unknown(report, "NESTED_DIRECTORY_BUDGET_LIMIT")
        return
    budget.entries -= 1
    name = name[:-3] if name.casefold().endswith(".gz") and len(name) > 3 else "gzip-content"
    entry = _stream_entry(report, name, len(expanded))
    report["_directory_parsed"] = True
    report["coverage"]["listed_entries"] = 1
    _consume_stream_entry(report, entry, name, expanded, budget, depth)


def _inspect_tar(data, report, budget, depth, ratio_cap):
    """Read only in-memory member slices; tarfile never creates or opens a path."""
    members = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:", errors="surrogateescape") as archive:
            for info in archive:
                if time.monotonic() >= budget.deadline:
                    _unknown(report, "MEMBER_DEADLINE")
                    return
                header_bytes = info.offset_data - info.offset
                if budget.entries < 1 or not 0 < header_bytes <= budget.central_bytes:
                    _unknown(report, "NESTED_DIRECTORY_BUDGET_LIMIT")
                    return
                budget.entries -= 1
                budget.central_bytes -= header_bytes
                members.append(info)
            end = archive.offset
            if (end < 0 or end + 1024 > len(data) or data[end:end + 1024] != bytes(1024)
                    or any(data[end + 1024:])):
                _unknown(report, "TAR_STRUCTURE_END_INVALID")
                return
    except (OSError, EOFError, ValueError, OverflowError, tarfile.TarError):
        _unknown(report, "TAR_STRUCTURE_HEADER_INVALID")
        return
    if sum(info.size for info in members if info.isreg()) > ratio_cap:
        _unknown(report, "NESTED_EXPANSION_RATIO_LIMIT")
        return
    seen, work, links, payloads = set(), [], set(), {}
    for info in members:
        name = info.name
        while name.startswith("./"):
            name = name[2:]
        if info.isdir() and name == ".":
            continue
        entry = _stream_entry(report, name, info.size, info.isdir())
        _validate_member_path(report, name, entry, seen)
        if info.isdir() and info.size:
            _unknown(report, "DIRECTORY_PAYLOAD_UNINSPECTED", entry)
        if info.issym() or info.islnk():
            index = entry["index"]
            links.add(index)
            entry["link"] = {"status": "UNRESOLVED"}
            target = info.linkname.encode("utf-8", errors="surrogateescape")
            if len(target) > LIMITS["path_bytes"]:
                _unknown(report, "ZIP_LINK_TARGET_SIZE_LIMIT", entry)
            elif not entry["issues"]:
                reason, value = _link_target(target)
                if not reason and info.islnk():
                    value = "../" * name.count("/") + value
                payloads[index] = (reason, value)
                entry["verified_sha256"] = hashlib.sha256(target).hexdigest()
        elif info.issparse():
            _unknown(report, "TAR_SPARSE_UNREAD", entry)
        elif not info.isdir() and not info.isreg():
            _unknown(report, "LINK_OR_SPECIAL_FILE_UNSUPPORTED", entry)
        if info.size < 0 or info.offset_data + info.size > len(data):
            _unknown(report, "TAR_STRUCTURE_MEMBER_SPAN_INVALID", entry)
        if info.size > budget.limits["member_bytes"]:
            _unknown(report, "MEMBER_SIZE_LIMIT", entry)
        # A ZipInfo here is a neutral name/type record for the same in-archive
        # path resolver; there is no local link read or directory extraction.
        nominal = zipfile.ZipInfo(name + "/" if info.isdir() and not name.endswith("/") else name or ".")
        work.append((nominal, entry, info))
    coverage = report["coverage"]
    report["_directory_parsed"] = True
    coverage["listed_entries"] = len(work)
    indexed = [(nominal, entry) for nominal, entry, _ in work]
    path_index = _link_index(report, indexed, links) if links else None
    for nominal, entry, info in work:
        if entry["issues"]:
            payloads.pop(entry["index"], None)
            coverage["uninspected_files"] += 1
        elif info.isdir():
            entry["text_status"] = "DIRECTORY"
            coverage["directories"] += 1
        elif entry["index"] not in links:
            start = info.offset_data
            _consume_stream_entry(report, entry, nominal.orig_filename, data[start:start + info.size], budget, depth)
        if entry["index"] not in links:
            budget.resolved(entry)
    if path_index is not None:
        _finish_links(report, indexed, path_index, links, payloads, budget)


def _inspect_level(data, report, budget, *, depth=0, inner_ratio_cap=None):
    deadline = budget.deadline
    limits = budget.limits
    if time.monotonic() >= deadline:
        _unknown(report, "MEMBER_DEADLINE")
        return
    try:
        directory_start, count, size = _directory_bound(data, limits)
    except ValueError as exc:
        _unknown(report, str(exc))
        return
    if count > budget.entries or size > budget.central_bytes:
        _unknown(report, "NESTED_DIRECTORY_BUDGET_LIMIT")
        return
    budget.entries -= count
    budget.central_bytes -= size
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            total = sum(info.file_size for info in infos)
            report["coverage"]["declared_total_member_bytes"] = total
            if inner_ratio_cap is not None and total > inner_ratio_cap:
                _unknown(report, "NESTED_EXPANSION_RATIO_LIMIT")
                return
            if total > limits["total_member_bytes"]:
                _unknown(report, "TOTAL_MEMBER_SIZE_LIMIT")
            report["_directory_parsed"] = True
            seen = set()
            links = set()
            for index, info in enumerate(infos):
                name = info.orig_filename
                entry = {
                    "index": index, "path": _display_path(name),
                    "compressed_bytes": info.compress_size, "uncompressed_bytes": info.file_size,
                    "expansion_ratio": round(info.file_size / max(1, info.compress_size), 3),
                    "compression_method": info.compress_type, "encrypted": bool(info.flag_bits & 1),
                    "directory": info.is_dir(), "issues": [], "text_status": "UNINSPECTABLE",
                    "read_budget_reserved": 0,
                }
                report["entries"].append(entry)
                _validate_member_path(report, name, entry, seen)
                kind = stat.S_IFMT(info.external_attr >> 16)
                if kind == stat.S_IFLNK and info.create_system == 3:
                    links.add(index)
                    entry["link"] = {"status": "UNRESOLVED"}
                    if info.file_size > limits["path_bytes"]:
                        _unknown(report, "ZIP_LINK_TARGET_SIZE_LIMIT", entry)
                elif kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    _unknown(report, "LINK_OR_SPECIAL_FILE_UNSUPPORTED", entry)
                encrypted = bool(info.flag_bits & 1)
                if encrypted:
                    _unknown(report, "ENCRYPTED_ENTRY_UNSUPPORTED", entry)
                if not encrypted and info.flag_bits & ~0x080F:
                    _unknown(report, "ZIP_FLAGS_UNSUPPORTED", entry)
                if not encrypted and info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    _unknown(report, "COMPRESSION_UNSUPPORTED", entry)
                if (not encrypted and info.extract_version > 20) or info.volume:
                    _unknown(report, "ZIP_VERSION_OR_VOLUME_UNSUPPORTED", entry)
                if info.is_dir() and (info.file_size or info.CRC):
                    _unknown(report, "DIRECTORY_PAYLOAD_UNINSPECTED", entry)
                if info.file_size > limits["member_bytes"]:
                    _unknown(report, "MEMBER_SIZE_LIMIT", entry)
                if info.file_size > limits["expansion_ratio"] * max(1, info.compress_size):
                    _unknown(report, "EXPANSION_RATIO_LIMIT", entry)
                pos = info.header_offset
                if not (0 <= pos and pos + 30 <= directory_start):
                    _unknown(report, "LOCAL_HEADER_OFFSET_INVALID", entry)
                elif data[pos:pos + 4] != b"PK\x03\x04":
                    _unknown(report, "LOCAL_HEADER_INVALID", entry)
                else:
                    header = struct.unpack_from("<4s5H3L2H", data, pos)
                    start = pos + 30 + header[-2] + header[-1]
                    if header[2:4] != (info.flag_bits, info.compress_type):
                        _unknown(report, "LOCAL_METADATA_MISMATCH", entry)
                    if not info.flag_bits & 8 and header[6:9] != (info.CRC, info.compress_size, info.file_size):
                        _unknown(report, "LOCAL_METADATA_MISMATCH", entry)
                    if start + info.compress_size > directory_start:
                        _unknown(report, "MEMBER_SPAN_INVALID", entry)
                    name_bytes = data[pos + 30:pos + 30 + header[-2]]
                    try:
                        local_name = name_bytes.decode("utf-8" if info.flag_bits & 0x800 else "cp437")
                    except UnicodeError:
                        local_name = None
                    if local_name != info.orig_filename:
                        _unknown(report, "LOCAL_NAME_MISMATCH", entry)
                    # ZipFile validates local names and overlapping entry spans
                    # without decompressing nonselected payloads.
                    if not entry["issues"]:
                        try:
                            with archive.open(info, "r"):
                                pass
                        except (OSError, EOFError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                            _unknown(report, "LOCAL_HEADER_UNREADABLE_" + type(exc).__name__, entry)
                if not encrypted and info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
                    _unknown(report, "STORED_SIZE_MISMATCH", entry)
            coverage = report["coverage"]
            coverage["listed_entries"] = len(infos)
            members = list(zip(infos, report["entries"]))
            path_index = _link_index(report, members, links) if links else None
            link_payloads = {}
            # Finish outer text opportunities before a ZIP/WHL consumes the shared budget.
            members.sort(key=lambda item: (
                Path(item[0].orig_filename).suffix.casefold() in NESTED_ZIP_SUFFIXES | NESTED_STREAM_SUFFIXES,
                _text_order(item, limits)))
            for info, entry in members:
                if info.is_dir() and not entry["issues"]:
                    entry["text_status"] = "DIRECTORY"
                    coverage["directories"] += 1
                    budget.resolved(entry)
                    continue
                if entry["issues"]:
                    coverage["uninspected_files"] += 1
                    budget.resolved(entry)
                    continue
                if time.monotonic() >= deadline:
                    _unknown(report, "MEMBER_DEADLINE", entry)
                    coverage["uninspected_files"] += 1
                    continue
                if info.file_size > budget.member_bytes:
                    _unknown(report, "MEMBER_READ_BUDGET_LIMIT", entry)
                    suffix = Path(info.orig_filename).suffix.casefold()
                    if suffix in NESTED_SUFFIXES | NESTED_ZIP_SUFFIXES | NESTED_STREAM_SUFFIXES:
                        _nested_summary(report, entry, "CANDIDATE", "UNREAD", {"MEMBER_READ_BUDGET_LIMIT": 1})
                    coverage["uninspected_files"] += 1
                    continue
                budget.member_bytes -= info.file_size
                entry["read_budget_reserved"] = info.file_size
                try:
                    digest, payload = _read_member(data, info, deadline, limits["text_bytes_each"])
                except (OSError, ValueError, zlib.error) as exc:
                    _unknown(report, str(exc) if isinstance(exc, ValueError) else "MEMBER_STREAM_UNREADABLE", entry)
                    coverage["uninspected_files"] += 1
                    continue
                entry["verified_sha256"] = digest
                if entry["index"] in links:
                    link_payloads[entry["index"]] = _link_target(payload)
                    continue
                suffix = Path(info.orig_filename).suffix.casefold()
                if suffix in NESTED_SUFFIXES | NESTED_STREAM_SUFFIXES or payload.startswith(CONTAINER_HEADERS) or payload[257:262] == b"ustar":
                    if suffix in NESTED_SUFFIXES and _archive_sidecar(info.orig_filename, payload, info.file_size):
                        _read_text(report, entry, info.orig_filename, payload, info.file_size, budget)
                    else:
                        _read_archive_member(report, entry, suffix, payload, budget, depth)
                else:
                    _read_text(report, entry, info.orig_filename, payload, info.file_size, budget)
                if entry["text_status"] == "UNINSPECTABLE":
                    coverage["uninspected_files"] += 1
                budget.resolved(entry)
            if path_index is not None:
                _finish_links(report, members, path_index, links, link_payloads, budget)
    except (OSError, EOFError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile, UnicodeError, zlib.error) as exc:
        _unknown(report, "ZIP_UNREADABLE_" + type(exc).__name__)


def inspect_zip_fd(fd: int) -> dict:
    """Inspect one inherited regular-file or pipe FD without an input path."""
    if not isinstance(fd, int) or fd < 0:
        raise ValueError("FD_MUST_BE_NONNEGATIVE_INTEGER")
    return inspect_zip(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip_path", nargs="?", help="One local ZIP; this MVP is validated with synthetic inputs only")
    parser.add_argument("--fd", type=int, help="Read one inherited regular-file or closed pipe FD, e.g. stdin FD 0")
    args = parser.parse_args(argv)
    if (args.zip_path is None) == (args.fd is None):
        parser.error("provide exactly one ZIP path or --fd")
    report = inspect_zip_fd(args.fd) if args.fd is not None else inspect_zip(args.zip_path)
    # ASCII JSON escapes untrusted control characters and bidi in terminal output.
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 2 if report["inspection_status"] == "UNKNOWN" else 0


if __name__ == "__main__":
    raise SystemExit(main())
