#!/usr/bin/env python3
import json
import os
import base64
import binascii
import hashlib
from pathlib import Path
from datetime import datetime
from html import escape as html_escape

IN_FILE = "main.jsonl"
FILES_DIR = "files"
OUT_HTML = "signal-dump.html"
OUT_TXT = "signal-dump.txt"
ME_LABEL = "Me"
CUSTOM_CSS_FILE = "custom.css"


# ------------------ JSON loading ------------------

def load_any_json(path: str):
    text = Path(path).read_text(encoding="utf-8", errors="replace").lstrip()

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        if "Extra data" not in str(e):
            raise

    # NDJSON
    objs = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            objs.append(json.loads(s))
        except json.JSONDecodeError:
            objs = []
            break
    if objs:
        return objs

    # concatenated
    decoder = json.JSONDecoder()
    i = 0
    n = len(text)
    objs = []
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        obj, j = decoder.raw_decode(text, i)
        objs.append(obj)
        i = j
    return objs


# ------------------ helpers ------------------

def walk(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from walk(v)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item)

def safe_str(x, default=""):
    try:
        if x is None:
            return default
        return str(x)
    except Exception:
        return default

def first_nonempty(*vals):
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""

def to_dt(ts):
    try:
        if ts is None:
            return None
        ts_int = int(ts)
        if ts_int > 10_000_000_000:
            ts_int = ts_int / 1000
        return datetime.fromtimestamp(ts_int)
    except Exception:
        return None

def name_from_contact(contact: dict) -> str:
    if not isinstance(contact, dict):
        return "Unknown"

    pg = safe_str(contact.get("profileGivenName")).strip()
    pf = safe_str(contact.get("profileFamilyName")).strip()
    prof = (pg + " " + pf).strip()
    if prof:
        return prof

    sg = safe_str(contact.get("systemGivenName")).strip()
    sf = safe_str(contact.get("systemFamilyName")).strip()
    sysn = (sg + " " + sf).strip()
    if sysn:
        return sysn

    e164 = safe_str(contact.get("e164")).strip()
    if e164:
        return e164 if e164.startswith("+") else f"+{e164}"

    return "Unknown"

def anchor_id(chat_id: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in safe_str(chat_id, "unknown"))
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return f"chat-{cleaned.strip('-') or 'unknown'}"

def b64_to_bytes(b64s: str) -> bytes:
    if not b64s:
        return b""
    try:
        return base64.b64decode(b64s, validate=False)
    except Exception:
        return b""


# ------------------ recipient / chat maps ------------------

def build_recipient_maps(data):
    recipient_name = {}
    group_title = {}

    for obj in walk(data):
        rec = obj.get("recipient")
        if not isinstance(rec, dict):
            continue

        rid = safe_str(rec.get("id"), default="")
        if not rid:
            continue

        contact = rec.get("contact")
        if isinstance(contact, dict):
            recipient_name[rid] = name_from_contact(contact)

        group = rec.get("group")
        if isinstance(group, dict):
            snap = group.get("snapshot")
            title = ""
            if isinstance(snap, dict):
                t = snap.get("title")
                if isinstance(t, dict):
                    title = safe_str(t.get("title")).strip()
                title = first_nonempty(title, safe_str(snap.get("name")), safe_str(group.get("name")))
            if title:
                group_title[rid] = title

    return recipient_name, group_title

def build_chat_titles(data, recipient_name, group_title):
    chat_title = {}
    for rid, title in group_title.items():
        chat_title[rid] = f"Group: {title}"
    for rid, name in recipient_name.items():
        chat_title.setdefault(rid, name)

    candidate_keys = ("chat", "conversation", "thread")
    for obj in walk(data):
        for key in candidate_keys:
            c = obj.get(key)
            if not isinstance(c, dict):
                continue
            cid = c.get("id") or c.get("chatId") or c.get("conversationId") or c.get("threadId")
            cid = safe_str(cid, default="")
            if not cid:
                continue
            title = first_nonempty(safe_str(c.get("title")), safe_str(c.get("name")), safe_str(c.get("displayName")))
            if title:
                chat_title[cid] = title
    return chat_title


# ------------------ attachment indexing: size -> path ------------------

def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def build_files_index(files_dir: str):
    base = Path(files_dir)
    paths_by_size = {}
    if not base.exists():
        return paths_by_size

    for root, _dirs, files in os.walk(base):
        for fn in files:
            p = Path(root) / fn
            try:
                size = p.stat().st_size
            except Exception:
                continue
            rel = p.relative_to(Path(".")).as_posix()  # files/xx/whatever
            paths_by_size.setdefault(size, []).append(rel)

    return paths_by_size

def resolve_attachment(pointer: dict, paths_by_size: dict):
    if not isinstance(pointer, dict):
        return {"path": "", "exists": False, "method": "no-pointer"}

    loc = pointer.get("locatorInfo")
    size = None
    ph_bytes = b""
    if isinstance(loc, dict):
        try:
            size = int(loc.get("size")) if loc.get("size") is not None else None
        except Exception:
            size = None
        ph_bytes = b64_to_bytes(safe_str(loc.get("plaintextHash"), default="").strip())

    if size is None:
        return {"path": "", "exists": False, "method": "no-size"}

    candidates = paths_by_size.get(size, [])
    if not candidates:
        return {"path": "", "exists": False, "method": "size-no-match"}

    if len(candidates) == 1:
        path = candidates[0]
        return {"path": path, "exists": Path(path).exists(), "method": "size-unique"}

    # If plaintextHash is a sha256 digest (32 bytes), compare
    if len(ph_bytes) == 32:
        ph_hex = binascii.hexlify(ph_bytes).decode("ascii")
        for rel in candidates:
            p = Path(rel)
            if not p.exists():
                continue
            try:
                if sha256_file(p) == ph_hex:
                    return {"path": rel, "exists": True, "method": "sha256-match"}
            except Exception:
                continue

    for rel in candidates:
        if Path(rel).exists():
            return {"path": rel, "exists": True, "method": "size-ambiguous"}
    return {"path": candidates[0], "exists": False, "method": "size-ambiguous-missing"}


# ------------------ reactions ------------------

def extract_reactions(chat_item):
    out = []
    if not isinstance(chat_item, dict):
        return out

    candidate_lists = []
    if isinstance(chat_item.get("reactions"), list):
        candidate_lists.append(chat_item["reactions"])

    std = chat_item.get("standardMessage")
    if isinstance(std, dict) and isinstance(std.get("reactions"), list):
        candidate_lists.append(std["reactions"])

    if isinstance(std, dict):
        t = std.get("text")
        if isinstance(t, dict) and isinstance(t.get("reactions"), list):
            candidate_lists.append(t["reactions"])

    for lst in candidate_lists:
        for r in lst:
            if not isinstance(r, dict):
                continue
            emoji = r.get("emoji") or r.get("reaction") or r.get("value")
            if isinstance(emoji, dict):
                emoji = emoji.get("value") or emoji.get("emoji")
            if emoji is None:
                continue
            author = r.get("authorId") or r.get("fromId") or r.get("senderId") or r.get("reactorId")
            removed = r.get("removed") or r.get("isRemoved") or False
            out.append({"emoji": safe_str(emoji), "authorId": safe_str(author, default=None) if author is not None else None, "removed": bool(removed)})
    return out


# ------------------ calls & deletions ------------------

def format_call_summary(call_obj: dict) -> str:
    if not isinstance(call_obj, dict):
        return "📞 Call"
    typ = safe_str(call_obj.get("type"), default="CALL")
    direction = safe_str(call_obj.get("direction"), default="UNKNOWN")
    state = safe_str(call_obj.get("state"), default="UNKNOWN")
    type_label = {"AUDIO_CALL": "Audio call", "VIDEO_CALL": "Video call"}.get(typ, typ)
    return f"📞 {type_label} — {direction} — {state}"

DELETED_MARKER = "🪦 Message deleted"


# ------------------ extract timeline items ------------------

def extract_items(data, recipient_name, paths_by_size):
    """
    rows:
      (dt, raw_ts, chatId, authorName, kind, body, reactions, attachments)
    kind: message | call | deleted
    """
    rows = []

    for obj in walk(data):
        chat_item = obj.get("chatItem")
        if not isinstance(chat_item, dict):
            continue

        chat_id = safe_str(chat_item.get("chatId"), default="unknown")
        author_id = safe_str(chat_item.get("authorId"), default="unknown")
        date_sent = chat_item.get("dateSent")

        is_incoming = isinstance(chat_item.get("incoming"), dict)
        mapped = recipient_name.get(author_id)
        author_name = mapped if mapped else (ME_LABEL if not is_incoming else f"id:{author_id}")

        # 1) standard message (text + attachments)
        std = chat_item.get("standardMessage")
        if isinstance(std, dict):
            body = ""
            t = std.get("text")
            if isinstance(t, dict):
                body = safe_str(t.get("body"), default="")

            attachments_out = []
            atts = std.get("attachments")
            if isinstance(atts, list):
                for a in atts:
                    if not isinstance(a, dict):
                        continue
                    ptr = a.get("pointer")
                    if not isinstance(ptr, dict):
                        continue

                    ctype = safe_str(ptr.get("contentType"), default="")
                    fname = safe_str(ptr.get("fileName"), default="")
                    res = resolve_attachment(ptr, paths_by_size)

                    attachments_out.append({
                        "contentType": ctype,
                        "fileName": fname,
                        "path": res["path"],
                        "exists": res["exists"],
                        "method": res["method"],
                    })

            if body or attachments_out:
                dt = to_dt(date_sent)
                reactions = extract_reactions(chat_item) if body else []
                rows.append((dt, date_sent, chat_id, author_name, "message", body, reactions, attachments_out))
                continue

        # 2) remote deleted message gravestone
        if "remoteDeletedMessage" in chat_item:
            # place it at dateSent
            dt = to_dt(date_sent)
            rows.append((dt, date_sent, chat_id, author_name, "deleted", DELETED_MARKER, [], []))
            continue

        # 3) call
        upd = chat_item.get("updateMessage")
        if isinstance(upd, dict):
            ic = upd.get("individualCall")
            if isinstance(ic, dict):
                ts = ic.get("startedCallTimestamp") or date_sent
                dt = to_dt(ts)
                summary = format_call_summary(ic)
                rows.append((dt, ts, chat_id, author_name, "call", summary, [], []))
                continue

    def sort_key(r):
        dt, raw_ts = r[0], r[1]
        if dt is not None:
            return (0, dt.timestamp())
        try:
            return (1, int(raw_ts))
        except Exception:
            return (2, 0)

    rows.sort(key=sort_key)
    return rows


# ------------------ output formatting ------------------

def reactions_txt(reactions, recipient_name):
    items = []
    for r in reactions:
        if r.get("removed"):
            continue
        emoji = r.get("emoji", "")
        rid = r.get("authorId")
        who = recipient_name.get(rid, f"id:{rid}") if rid else "Unknown"
        items.append(f"{emoji} {who}")
    return ("  [reactions: " + "; ".join(items) + "]") if items else ""

def reactions_html(reactions, recipient_name):
    chips = []
    for r in reactions:
        if r.get("removed"):
            continue
        emoji = html_escape(r.get("emoji", ""))
        rid = r.get("authorId")
        who = recipient_name.get(rid, f"id:{rid}") if rid else "Unknown"
        chips.append(f"<span class='rxn' title='{html_escape(who)}'>{emoji}</span>")
    return ("<div class='rxns'>" + "".join(chips) + "</div>") if chips else ""

def group_by_chat(rows):
    chats = {}
    for r in rows:
        chats.setdefault(r[2], []).append(r)
    return chats

def attachment_txt(a):
    fname = a.get("fileName") or ""
    ctype = a.get("contentType") or ""
    path = a.get("path") or ""
    label = fname if fname else (Path(path).name if path else "attachment")
    method = a.get("method", "")
    if path:
        return f"[{label}] ({ctype}) -> {path} ({method})".strip()
    return f"[{label}] ({ctype}) ({method})".strip()

def attachment_html(a):
    ctype = a.get("contentType") or ""
    path = a.get("path") or ""
    fname = a.get("fileName") or ""
    exists = a.get("exists", False)
    method = a.get("method", "")

    label = fname if fname else (Path(path).name if path else "attachment")
    label_esc = html_escape(label)
    ctype_esc = html_escape(ctype)

    if not path:
        return f"<div class='att unresolved'>📎 {label_esc} <span class='muted'>{ctype_esc}</span></div>"

    url = html_escape(path)
    missing = "" if exists else "<span class='missing'>⚠️ missing on disk</span>"
    meth = f"<span class='muted'>[{html_escape(method)}]</span>" if method else ""
    link = f"<a href='{url}' target='_blank' rel='noopener'>📎 {label_esc}</a> <span class='muted'>{ctype_esc}</span> {meth} {missing}"

    if ctype.startswith("image/"):
        return (
            "<div class='att'>"
            f"<a href='{url}' target='_blank' rel='noopener'>"
            f"<img src='{url}' alt='{label_esc}' loading='lazy' />"
            "</a>"
            f"<div class='attcap'>{link}</div>"
            "</div>"
        )
    if ctype.startswith("video/"):
        return (
            "<div class='att'>"
            f"<video controls preload='metadata' src='{url}'></video>"
            f"<div class='attcap'>{link}</div>"
            "</div>"
        )
    if ctype.startswith("audio/"):
        return (
            "<div class='att'>"
            f"<audio controls preload='metadata' src='{url}'></audio>"
            f"<div class='attcap'>{link}</div>"
            "</div>"
        )
    return f"<div class='att'>{link}</div>"

def write_txt(rows, chat_title, recipient_name, out_path):
    chats = group_by_chat(rows)

    index_items = []
    for chat_id, items in chats.items():
        title = chat_title.get(chat_id, f"Chat {chat_id}")
        index_items.append((title.lower(), title, chat_id, len(items)))
    index_items.sort(key=lambda x: x[0])

    lines = []
    lines.append("Signal export transcript\n")
    lines.append(f"Chats: {len(chats)}  Items: {len(rows)}\n")
    lines.append("INDEX (search for the exact header below)\n")
    for _tlow, title, chat_id, count in index_items:
        lines.append(f"- {title}  [chatId={chat_id}]  ({count})")
    lines.append("\n" + "=" * 80 + "\n")

    for _tlow, title, chat_id, _count in index_items:
        items = chats[chat_id]
        lines.append("\n" + "=" * 80)
        lines.append(f"{title}  (chatId={chat_id})")
        lines.append("=" * 80)

        for dt, raw_ts, _cid, author_name, kind, body, reactions, attachments in items:
            when = dt.isoformat(sep=" ", timespec="seconds") if dt else safe_str(raw_ts)
            if kind == "message":
                base = f"[{when}] {author_name}: {body}".rstrip()
                if reactions:
                    base += reactions_txt(reactions, recipient_name)
                lines.append(base)
                if attachments:
                    for a in attachments:
                        lines.append(f"    {attachment_txt(a)}")
            else:
                # call or deleted
                lines.append(f"[{when}] {author_name}: {body}")

    Path(out_path).write_text("\n".join(lines), encoding="utf-8")

def write_html(rows, chat_title, recipient_name, out_path):
    chats = group_by_chat(rows)

    index_items = []
    for chat_id, items in chats.items():
        title = chat_title.get(chat_id, f"Chat {chat_id}")
        index_items.append((title.lower(), title, chat_id, len(items)))
    index_items.sort(key=lambda x: x[0])

    base_css = """
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:1120px;margin:24px auto;padding:0 14px;line-height:1.35}
    h1{margin:0 0 10px 0}
    .meta{color:#666;font-size:12px;margin:0 0 16px 0}
    .index{border:1px solid #ddd;border-radius:14px;padding:12px 14px;margin:14px 0 22px 0}
    .index h2{margin:0 0 10px 0;font-size:16px}
    .index ul{margin:0;padding-left:18px;columns:2;column-gap:28px}
    .index li{margin:6px 0;break-inside:avoid}
    .count{color:#666;font-size:12px;margin-left:6px}
    .chat{margin:26px 0 44px 0}
    .chat h2{margin:0 0 10px 0;font-size:18px}
    .chat .toplink{font-size:12px;color:#666;margin:0 0 14px 0}
    .msg{border:1px solid #ddd;border-radius:12px;padding:10px 12px;margin:10px 0;overflow:hidden}
    .hdr{display:flex;gap:10px;flex-wrap:wrap;align-items:baseline}
    .who{font-weight:650}
    .when{color:#666;font-size:12px}
    .body{white-space:pre-wrap;margin-top:6px;overflow-wrap:anywhere}
    .rxns{margin-top:8px;display:flex;gap:6px;flex-wrap:wrap}
    .rxn{border:1px solid #ddd;border-radius:999px;padding:2px 8px;font-size:13px}
    .call{border-style:dashed}
    .deleted{border-style:dotted;opacity:0.85}
    .att{margin-top:10px}
    .att img{width:100%;max-width:100%;height:auto;max-height:80vh;object-fit:contain;border:1px solid #ddd;border-radius:10px;display:block}
    .att video{display:block;width:100% !important;max-width:100% !important;height:auto !important; max-height:80vh;object-fit:contain;border:1px solid #ddd;border-radius:10px;}
    .att audio{width:100%}
    .attcap{color:#444;font-size:12px;margin-top:6px;word-break:break-word;overflow-wrap:anywhere}
    .muted{color:#777;font-size:12px;margin-left:8px}
    .unresolved{opacity:0.75}
    .missing{color:#b00;font-size:12px;margin-left:10px}
    a{color:inherit}
    """

    css_path = Path(CUSTOM_CSS_FILE)
    if not css_path.exists():
        css_path.write_text("/* Put your custom overrides here. Linked by signal-dump.html */\n", encoding="utf-8")

    parts = []
    parts.append("<!doctype html><meta charset='utf-8'>")
    parts.append("<title>Signal dump</title>")
    parts.append(f"<style>\n{base_css}\n</style>")
    parts.append(f"<link rel='stylesheet' href='{html_escape(CUSTOM_CSS_FILE)}'>")
    parts.append("<a id='index'></a>")
    parts.append("<h1>Signal dump</h1>")
    parts.append(f"<p class='meta'>Chats: {len(chats)} • Items: {len(rows)}</p>")

    parts.append("<div class='index'>")
    parts.append("<h2>Index</h2>")
    parts.append("<ul>")
    for _tlow, title, chat_id, count in index_items:
        aid = anchor_id(chat_id)
        parts.append(f"<li><a href='#{aid}'>{html_escape(title)}</a><span class='count'>({count})</span></li>")
    parts.append("</ul>")
    parts.append("</div>")

    for _tlow, title, chat_id, _count in index_items:
        items = chats[chat_id]
        aid = anchor_id(chat_id)

        parts.append("<div class='chat'>")
        parts.append(f"<a id='{aid}'></a>")
        parts.append(f"<h2>{html_escape(title)}</h2>")
        parts.append(f"<div class='toplink'><a href='#index'>Back to index</a> • chatId={html_escape(chat_id)}</div>")

        for dt, raw_ts, _cid, author_name, kind, body, reactions, attachments in items:
            when = dt.isoformat(sep=" ", timespec="seconds") if dt else safe_str(raw_ts)
            cls = "msg"
            if kind == "call":
                cls = "msg call"
            elif kind == "deleted":
                cls = "msg deleted"

            parts.append(f"<div class='{cls}'>")
            parts.append("<div class='hdr'>"
                         f"<span class='who'>{html_escape(author_name)}</span>"
                         f"<span class='when'>{html_escape(when)}</span>"
                         "</div>")

            if body:
                parts.append(f"<div class='body'>{html_escape(body)}</div>")
            elif kind == "message" and attachments:
                parts.append("<div class='body muted'>(attachment)</div>")
            else:
                parts.append(f"<div class='body'>{html_escape(body)}</div>")

            if kind == "message" and reactions:
                rx = reactions_html(reactions, recipient_name)
                if rx:
                    parts.append(rx)

            if kind == "message" and attachments:
                for a in attachments:
                    parts.append(attachment_html(a))

            parts.append("</div>")

        parts.append("</div>")

    Path(out_path).write_text("\n".join(parts), encoding="utf-8")


# ------------------ main ------------------

def main():
    in_path = Path(IN_FILE)
    if not in_path.exists():
        print(f"ERROR: Can't find input file: {IN_FILE}")
        print("Tip: set IN_FILE at top of convert.py to your actual JSON filename.")
        print("Files in this folder:")
        for p in Path(".").iterdir():
            if p.is_file():
                print(" -", p.name)
        return

    data = load_any_json(IN_FILE)
    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        data = [data]

    recipient_name, group_title = build_recipient_maps(data)
    chat_title = build_chat_titles(data, recipient_name, group_title)

    paths_by_size = build_files_index(FILES_DIR)
    if Path(FILES_DIR).exists():
        total_files = sum(len(v) for v in paths_by_size.values())
        print(f"Indexed {total_files} files under ./{FILES_DIR}/ (by file size)")
    else:
        print(f"NOTE: no ./{FILES_DIR}/ directory found; attachments won't link.")

    rows = extract_items(data, recipient_name, paths_by_size)

    write_html(rows, chat_title, recipient_name, OUT_HTML)
    write_txt(rows, chat_title, recipient_name, OUT_TXT)

    print(f"Wrote: {OUT_HTML}")
    print(f"Wrote: {OUT_TXT}")
    print(f"Also created/updated: {CUSTOM_CSS_FILE}")
    print(f"Items: {len(rows)} • Recipients: {len(recipient_name)} • Groups: {len(group_title)} • Chats titled: {len(chat_title)}")

if __name__ == "__main__":
    main()
