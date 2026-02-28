import hashlib
import json
import threading
import tkinter as tk
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, X, BooleanVar, StringVar, Tk, filedialog, messagebox, ttk
from typing import Any, Callable, Mapping, cast

import requests

PayloadDict = dict[str, str]
ResponseDict = dict[str, Any]


@dataclass
class SealedPayload:
    creatorId: str
    title: str
    description: str
    videoUrl: str
    originBundleId: str
    assetId: str
    keyId: str
    contentHash: str
    originId: str


class OriginCreatorTool:
    def __init__(self, root: Tk) -> None:
        self.root = root
        root.title("Origin Creator Tool")
        root.geometry("1040x700")
        root.configure(bg="#060b17")

        self.api_base = StringVar(value="https://originapp.fly.dev/api")
        self.ingest_key = StringVar(value="")
        self.creator_id = StringVar(value="")
        self.key_id = StringVar(value="")
        self.origin_id = StringVar(value="")
        self.file_path = StringVar(value="")
        self.video_url = StringVar(value="")
        self.title = StringVar(value="")
        self.description = StringVar(value="")
        self.bundle_id = StringVar(value="")
        self.asset_id = StringVar(value="")
        self.content_hash = StringVar(value="")
        self.busy = BooleanVar(value=False)
        self.show_advanced = BooleanVar(value=False)
        self.advanced_frame: ttk.Frame | None = None

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure("Root.TFrame", background="#060b17")
        style.configure("Card.TFrame", background="#0b1220", borderwidth=0, relief="flat")
        style.configure("Header.TLabel", background="#0b1220", foreground="#e5e7eb", font=("Segoe UI", 12, "bold"))
        style.configure("Body.TLabel", background="#0b1220", foreground="#cbd5e1", font=("Segoe UI", 9))
        style.configure("Label.TLabel", background="#0b1220", foreground="#cbd5e1", font=("Segoe UI", 9))
        style.configure("Hint.TLabel", background="#0b1220", foreground="#93c5fd", font=("Segoe UI", 8))
        style.configure(
            "TEntry",
            fieldbackground="#0f172a",
            foreground="#e5e7eb",
            bordercolor="#0f172a",
            lightcolor="#0f172a",
            darkcolor="#0f172a",
            relief="flat",
            borderwidth=0,
            padding=4,
        )
        style.configure("TButton", background="#1e293b", foreground="#e5e7eb", borderwidth=0, relief="flat", padding=(10, 5))
        style.map("TButton", background=[("active", "#334155")], foreground=[("active", "#ffffff")])
        style.configure("TCheckbutton", background="#0b1220", foreground="#cbd5e1")
        style.map("TCheckbutton", background=[("active", "#0b1220")], foreground=[("active", "#e5e7eb")])
        style.configure("Log.Treeview", background="#020617", fieldbackground="#020617", foreground="#e5e7eb", borderwidth=0)
        style.configure("Log.Treeview.Heading", background="#111827", foreground="#e5e7eb", relief="flat", borderwidth=0)

    def _section_card(self, parent: ttk.Frame, title: str, subtitle: str | None = None) -> ttk.Frame:
        card = ttk.Frame(parent, padding=8, style="Card.TFrame")
        card.pack(fill=X, pady=4)
        ttk.Label(card, text=title, style="Header.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(card, text=subtitle, style="Body.TLabel").pack(anchor="w", pady=(1, 6))
        return card

    def _grid_row(self, parent: ttk.Frame, row: int, label: str, variable: StringVar, column: int = 0) -> ttk.Entry:
        label_col = 0 if column == 0 else 3
        entry_col = 1 if column == 0 else 4
        ttk.Label(parent, text=label, style="Label.TLabel").grid(row=row, column=label_col, sticky="w", padx=(0, 8), pady=2)
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=entry_col, sticky="ew", pady=2)
        return entry

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, padding=8, style="Root.TFrame")
        frame.pack(fill=BOTH, expand=True)

        title_row = ttk.Frame(frame, style="Root.TFrame")
        title_row.pack(fill=X, pady=(0, 4))
        ttk.Label(title_row, text="Origin Creator Tool", style="Header.TLabel").pack(side=LEFT)
        ttk.Label(
            title_row,
            text="Choose file → Seal → Verify → Publish",
            style="Hint.TLabel",
        ).pack(side=RIGHT)

        config_card = self._section_card(frame, "Connection")
        config_grid = ttk.Frame(config_card, style="Card.TFrame")
        config_grid.pack(fill=X)
        config_grid.columnconfigure(1, weight=1)
        self._grid_row(config_grid, 0, "API Base URL", self.api_base)

        adv_toggle = ttk.Checkbutton(
            config_card,
            text="Show advanced connection fields",
            variable=self.show_advanced,
            command=self._toggle_advanced,
        )
        adv_toggle.pack(anchor="w", pady=(4, 0))

        self.advanced_frame = ttk.Frame(config_card, style="Card.TFrame")
        self.advanced_frame.pack(fill=X, pady=(4, 0))
        self.advanced_frame.columnconfigure(1, weight=1)
        self._grid_row(self.advanced_frame, 0, "Ingest Key (optional)", self.ingest_key)
        self._grid_row(self.advanced_frame, 1, "Origin ID (optional)", self.origin_id)

        content_card = self._section_card(frame, "Content", "Select a source file and required metadata.")
        drop_hint = tk.Label(
            content_card,
            text="Drop area (click Browse below): select a video/image to seal",
            bg="#020617",
            fg="#cbd5e1",
            bd=0,
            relief="flat",
            padx=10,
            pady=7,
        )
        drop_hint.pack(fill=X, pady=(0, 6))

        file_row = ttk.Frame(content_card, style="Card.TFrame")
        file_row.pack(fill=X, pady=(0, 6))
        ttk.Label(file_row, text="Content File", style="Label.TLabel").pack(side=LEFT)
        ttk.Entry(file_row, textvariable=self.file_path).pack(side=LEFT, fill=X, expand=True, padx=(10, 10))
        ttk.Button(file_row, text="Browse", command=self.pick_file).pack(side=RIGHT)

        content_grid = ttk.Frame(content_card, style="Card.TFrame")
        content_grid.pack(fill=X)
        content_grid.columnconfigure(1, weight=1)
        content_grid.columnconfigure(4, weight=1)

        self._grid_row(content_grid, 0, "Creator ID", self.creator_id, column=0)
        self._grid_row(content_grid, 0, "Asset ID", self.asset_id, column=1)
        self._grid_row(content_grid, 1, "Title", self.title, column=0)
        self._grid_row(content_grid, 1, "Bundle ID", self.bundle_id, column=1)
        self._grid_row(content_grid, 2, "Description", self.description, column=0)
        self._grid_row(content_grid, 2, "Key ID", self.key_id, column=1)
        self._grid_row(content_grid, 3, "Video URL", self.video_url, column=0)
        self._grid_row(content_grid, 3, "Content Hash", self.content_hash, column=1)

        for spacer_col in (2, 5):
            content_grid.columnconfigure(spacer_col, minsize=14)

        flow_card = self._section_card(frame, "Workflow")
        actions = ttk.Frame(flow_card, style="Card.TFrame")
        actions.pack(fill=X, pady=(0, 4))
        ttk.Button(actions, text="1) Seal Content", command=self.seal_content).pack(side=LEFT)
        ttk.Button(actions, text="2) Verify", command=self.verify_bundle).pack(side=LEFT, padx=6)
        ttk.Button(actions, text="3) Publish to Social", command=self.publish_sealed).pack(side=LEFT)

        secondary = ttk.Frame(flow_card, style="Card.TFrame")
        secondary.pack(fill=X)
        ttk.Button(secondary, text="Save Payload JSON", command=self.save_payload_json).pack(side=LEFT)
        ttk.Button(secondary, text="Load Payload JSON", command=self.load_payload_json).pack(side=LEFT, padx=6)
        ttk.Button(secondary, text="Clear", command=self.clear_fields).pack(side=LEFT)

        log_card = self._section_card(frame, "Activity Log")
        self.log = ttk.Treeview(log_card, columns=("message",), show="headings", height=8, style="Log.Treeview")
        self.log.heading("message", text="Message")
        self.log.column("message", width=980, anchor="w")
        self.log.pack(fill=BOTH, expand=True)

        self._toggle_advanced()

    def _toggle_advanced(self) -> None:
        if not self.advanced_frame:
            return
        if self.show_advanced.get():
            self.advanced_frame.pack(fill=X, pady=(8, 0))
        else:
            self.advanced_frame.pack_forget()

    def log_message(self, message: str) -> None:
        self.log.insert("", END, values=(message,))
        children = self.log.get_children()
        if children:
            self.log.see(children[-1])

    def pick_file(self) -> None:
        selected = filedialog.askopenfilename(title="Select content file")
        if selected:
            self.file_path.set(selected)
            if not self.title.get().strip():
                self.title.set(Path(selected).stem)
            if not self.asset_id.get().strip():
                self.asset_id.set(Path(selected).name)

    def clear_fields(self) -> None:
        self.file_path.set("")
        self.video_url.set("")
        self.title.set("")
        self.description.set("")
        self.bundle_id.set("")
        self.asset_id.set("")
        self.content_hash.set("")

    def seal_content(self) -> None:
        try:
            path = Path(self.file_path.get().strip())
            if not path.exists():
                messagebox.showerror("Missing file", "Select a valid content file first.")
                return

            digest = self._sha256(path)
            self.content_hash.set(digest)
            if not self.bundle_id.get().strip():
                self.bundle_id.set(f"bundle_{uuid.uuid4().hex[:16]}")
            if not self.asset_id.get().strip():
                self.asset_id.set(path.name)
            if not self.title.get().strip():
                self.title.set(path.stem)

            self.log_message(f"Sealed: {path.name} | hash={digest[:16]}... bundle={self.bundle_id.get()}")
        except Exception as exc:
            messagebox.showerror("Seal failed", str(exc))

    def verify_bundle(self) -> None:
        payload = self._build_verify_payload()
        if not payload:
            return

        def task() -> None:
            try:
                self.log_message("Verifying with Origin API…")
                res = self._request("POST", "/origin/verify", json_body=payload)
                self.log_message(f"Verify success: {json.dumps(res)[:500]}")
            except Exception as exc:
                self.log_message(f"Verify failed: {exc}")
                messagebox.showerror("Verify failed", str(exc))

        self._run_async(task)

    def publish_sealed(self) -> None:
        payload = self._build_publish_payload()
        if not payload:
            return

        def task() -> None:
            try:
                self.log_message("Publishing sealed payload…")
                try:
                    res = self._request("POST", "/videos/sync/sealed", json_body=payload)
                except Exception:
                    res = self._request("POST", "/videos/sealed", json_body=payload)
                self.log_message(f"Publish success: {json.dumps(res)[:500]}")
            except Exception as exc:
                self.log_message(f"Publish failed: {exc}")
                messagebox.showerror("Publish failed", str(exc))

        self._run_async(task)

    def save_payload_json(self) -> None:
        payload = self._build_publish_payload(require_video_url=False)
        if not payload:
            return

        target = filedialog.asksaveasfilename(
            title="Save sealed payload",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile="sealed_payload.json",
        )
        if not target:
            return

        Path(target).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.log_message(f"Saved payload: {target}")

    def load_payload_json(self) -> None:
        source = filedialog.askopenfilename(title="Load sealed payload", filetypes=[("JSON", "*.json")])
        if not source:
            return

        raw = json.loads(Path(source).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            messagebox.showerror("Invalid payload", "Payload JSON must be an object.")
            return

        data = cast(dict[str, Any], raw)
        self.creator_id.set(self._as_text(data.get("creatorId")))
        self.title.set(self._as_text(data.get("title")))
        self.description.set(self._as_text(data.get("description")))
        self.video_url.set(self._as_text(data.get("videoUrl")))
        self.bundle_id.set(self._as_text(data.get("originBundleId")))
        self.asset_id.set(self._as_text(data.get("assetId")))
        self.key_id.set(self._as_text(data.get("keyId")))
        self.content_hash.set(self._as_text(data.get("contentHash")))
        self.origin_id.set(self._as_text(data.get("originId")))
        self.log_message(f"Loaded payload: {source}")

    def _build_verify_payload(self) -> PayloadDict | None:
        creator_id = self.creator_id.get().strip()
        key_id = self.key_id.get().strip()
        asset_id = self.asset_id.get().strip()
        content_hash = self.content_hash.get().strip()
        origin_id = self.origin_id.get().strip()

        if not creator_id or not key_id or not asset_id or not content_hash:
            messagebox.showerror("Missing fields", "Creator ID, Key ID, Asset ID, and Content Hash are required for verify.")
            return None

        body: PayloadDict = {
            "creatorId": creator_id,
            "keyId": key_id,
            "assetId": asset_id,
            "contentHash": content_hash,
        }
        if origin_id:
            body["originId"] = origin_id
        return body

    def _build_publish_payload(self, require_video_url: bool = True) -> PayloadDict | None:
        payload = SealedPayload(
            creatorId=self.creator_id.get().strip(),
            title=self.title.get().strip(),
            description=self.description.get().strip(),
            videoUrl=self.video_url.get().strip(),
            originBundleId=self.bundle_id.get().strip(),
            assetId=self.asset_id.get().strip(),
            keyId=self.key_id.get().strip(),
            contentHash=self.content_hash.get().strip(),
            originId=self.origin_id.get().strip(),
        )

        if not payload.title or not payload.assetId or not payload.keyId or not payload.contentHash:
            messagebox.showerror(
                "Missing fields",
                "Title, Asset ID, Key ID, and Content Hash are required for publishing sealed content.",
            )
            return None

        if require_video_url and not payload.videoUrl:
            messagebox.showerror("Missing video URL", "Video URL is required to publish to social.")
            return None

        body = cast(PayloadDict, asdict(payload))
        if not body["creatorId"]:
            body.pop("creatorId")
        if not body["description"]:
            body.pop("description")
        if not body["originBundleId"]:
            body.pop("originBundleId")
        if not body["originId"]:
            body.pop("originId")
        if not body["videoUrl"]:
            body.pop("videoUrl")
        return body

    def _request(self, method: str, path: str, json_body: Mapping[str, Any]) -> ResponseDict:
        api_base = self.api_base.get().strip().rstrip("/")
        if not api_base:
            raise RuntimeError("API base URL is required.")

        url = f"{api_base}{path}"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        ingest = self.ingest_key.get().strip()
        if ingest:
            headers["X-Origin-Ingest-Key"] = ingest

        response = requests.request(method, url, headers=headers, json=json_body, timeout=35)
        response.raise_for_status()
        if not response.text.strip():
            return {"ok": True}
        parsed = response.json()
        if isinstance(parsed, dict):
            return cast(ResponseDict, parsed)
        return {"data": parsed}

    def _run_async(self, fn: Callable[[], None]) -> None:
        if self.busy.get():
            return
        self.busy.set(True)

        def wrapped() -> None:
            try:
                fn()
            finally:
                self.busy.set(False)

        threading.Thread(target=wrapped, daemon=True).start()

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as file_obj:
            for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _as_text(value: Any) -> str:
        if value is None:
            return ""
        return str(value)


def main() -> None:
    root = Tk()
    app = OriginCreatorTool(root)
    app.log_message("Ready. Seal content, verify bundle, then publish to Origin Social.")
    root.mainloop()


if __name__ == "__main__":
    main()
