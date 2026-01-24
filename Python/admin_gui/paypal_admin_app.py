from __future__ import annotations

import hashlib
import json
import os
import sys
import tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any

ENV_PATH = Path(os.environ.get("ORIGIN_ENV_PATH", str(Path(__file__).resolve().parents[1] / ".env")))
APP_DIR = Path.home() / ".origin_protocol"
AUTH_STATE_PATH = Path(os.environ.get("ORIGIN_AUTH_STATE", str(APP_DIR / "authority_state.json")))
EVENT_LOG_PATH = Path(os.environ.get("ORIGIN_EVENT_LOG", str(APP_DIR / "ipn_events.jsonl")))
LICENSE_INDEX_PATH = Path(os.environ.get("ORIGIN_LICENSE_INDEX", str(APP_DIR / "license_index.jsonl")))
LEDGER_PATH = Path(os.environ.get("ORIGIN_LICENSE_LEDGER", str(APP_DIR / "license_ledger.json")))
NODE_LEDGER_PATH = Path(os.environ.get("ORIGIN_NODE_LEDGER", str(APP_DIR / "node_ledger.json")))
DEFAULT_ISSUER_DIR = APP_DIR / "issuer_keys"
LEDGER_PRIVATE_KEY = os.environ.get(
    "ORIGIN_LEDGER_PRIVATE_KEY",
    str(DEFAULT_ISSUER_DIR / "private_key.ed25519"),
)
LEDGER_PUBLIC_KEY = os.environ.get(
    "ORIGIN_LEDGER_PUBLIC_KEY",
    str(DEFAULT_ISSUER_DIR / "public_key.ed25519"),
)
LICENSE_PRIVATE_KEY = os.environ.get(
    "ORIGIN_LICENSE_PRIVATE_KEY",
    str(DEFAULT_ISSUER_DIR / "private_key.ed25519"),
)
LICENSE_PUBLIC_KEY = os.environ.get(
    "ORIGIN_LICENSE_PUBLIC_KEY",
    str(DEFAULT_ISSUER_DIR / "public_key.ed25519"),
)
LICENSE_OUTPUT_DIR = Path(os.environ.get("ORIGIN_LICENSE_OUTPUT", str(APP_DIR / "licenses")))
DEFAULT_PLAN = os.environ.get("ORIGIN_PLAN_NAME", "pro")
DEFAULT_PLAN_DAYS = int(os.environ.get("ORIGIN_PLAN_DAYS", "30"))
PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
BOOTSTRAP_PATH = Path(os.environ.get("ORIGIN_BOOTSTRAP_PATH", str(PROJECT_ROOT / "creator_gui" / "ledger_bootstrap.json")))
GOVERNANCE_CONFIG_PATH = Path(os.environ.get("ORIGIN_GOVERNANCE_CONFIG", str(APP_DIR / "governance_config.json")))

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from origin_protocol.keys import generate_keypair, load_private_key, save_keypair
from origin_protocol.license import (
    LicenseLedgerEntry,
    add_license_ledger_entry,
    build_license,
    build_license_ledger,
    read_license_ledger_file,
    sign_license,
    sign_license_ledger,
    write_license_file,
    write_license_ledger_file,
)
from origin_protocol.nodes import (
    NodeAuthoritySignature,
    NodeDemotionCertificate,
    NodePromotionCertificate,
    add_node_ledger_entry,
    build_demotion_entry,
    build_node_ledger,
    build_promotion_entry,
    build_revocation_entry,
    read_node_ledger_file,
    sign_node_ledger,
    write_node_ledger_file,
)


def _load_env(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env(ENV_PATH)


class PayPalAdminApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Origin Protocol — PayPal Admin")
        self.geometry("900x600")
        self.configure(bg="#0f1115")
        self.authority_state: dict[str, Any] = {}
        self.authority_frame: tk.LabelFrame | None = None
        self.output_frame: tk.Frame | None = None
        self.output_visible = True
        self.governance_config: dict[str, Any] | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        header = tk.Label(
            self,
            text="Authority Admin Dashboard",
            fg="#e5e7eb",
            bg="#0f1115",
            font=("Segoe UI", 16, "bold"),
        )
        header.pack(pady=(18, 6))

        self.authority_frame = tk.LabelFrame(
            self,
            text="Authority node (decentralized controls)",
            fg="#cbd5e1",
            bg="#0f1115",
            padx=10,
            pady=10,
        )
        self.authority_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        paths_frame = tk.Frame(self.authority_frame, bg="#0f1115")
        paths_frame.pack(fill="x")

        tk.Label(paths_frame, text="Event log", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=0, padx=6, pady=4, sticky="w"
        )
        self.event_log_entry = tk.Entry(paths_frame, width=48)
        self.event_log_entry.grid(row=0, column=1, padx=6, pady=4, sticky="w")
        self.event_log_entry.insert(0, str(EVENT_LOG_PATH))
        tk.Button(
            paths_frame,
            text="Refresh metrics",
            command=self.refresh_metrics,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=0, column=2, padx=6, pady=4)

        tk.Label(paths_frame, text="Ledger", fg="#cbd5e1", bg="#0f1115").grid(
            row=1, column=0, padx=6, pady=4, sticky="w"
        )
        self.ledger_entry = tk.Entry(paths_frame, width=48)
        self.ledger_entry.grid(row=1, column=1, padx=6, pady=4, sticky="w")
        self.ledger_entry.insert(0, str(LEDGER_PATH))
        tk.Button(
            paths_frame,
            text="Export ledger",
            command=self.export_ledger,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=1, column=2, padx=6, pady=4)
        tk.Button(
            paths_frame,
            text="Copy ledger CID",
            command=self.copy_ledger_cid,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=1, column=3, padx=6, pady=4)

        tk.Label(paths_frame, text="Node ledger", fg="#cbd5e1", bg="#0f1115").grid(
            row=2, column=0, padx=6, pady=4, sticky="w"
        )
        self.node_ledger_entry = tk.Entry(paths_frame, width=48)
        self.node_ledger_entry.grid(row=2, column=1, padx=6, pady=4, sticky="w")
        self.node_ledger_entry.insert(0, str(NODE_LEDGER_PATH))
        tk.Button(
            paths_frame,
            text="Init node ledger",
            command=self.init_node_ledger,
            bg="#0b1220",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=2, column=2, padx=6, pady=4)
        tk.Button(
            paths_frame,
            text="Copy node CID",
            command=self.copy_node_ledger_cid,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=2, column=3, padx=6, pady=4)

        tk.Label(paths_frame, text="Bootstrap", fg="#cbd5e1", bg="#0f1115").grid(
            row=3, column=0, padx=6, pady=4, sticky="w"
        )
        self.bootstrap_entry = tk.Entry(paths_frame, width=48)
        self.bootstrap_entry.grid(row=3, column=1, padx=6, pady=4, sticky="w")
        self.bootstrap_entry.insert(0, str(BOOTSTRAP_PATH))
        tk.Button(
            paths_frame,
            text="Update bootstrap",
            command=self.update_bootstrap,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=3, column=2, padx=6, pady=4)
        tk.Button(
            paths_frame,
            text="Open",
            command=self.open_bootstrap,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=3, column=3, padx=6, pady=4)

        tk.Label(paths_frame, text="Governance config", fg="#cbd5e1", bg="#0f1115").grid(
            row=4, column=0, padx=6, pady=4, sticky="w"
        )
        self.governance_config_entry = tk.Entry(paths_frame, width=48)
        self.governance_config_entry.grid(row=4, column=1, padx=6, pady=4, sticky="w")
        self.governance_config_entry.insert(0, str(GOVERNANCE_CONFIG_PATH))
        tk.Button(
            paths_frame,
            text="Refresh from config",
            command=self.refresh_governance_config,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=4, column=2, padx=6, pady=4)
        tk.Button(
            paths_frame,
            text="Open",
            command=self.open_governance_config,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=4, column=3, padx=6, pady=4)

        keys_frame = tk.Frame(self.authority_frame, bg="#0f1115")
        keys_frame.pack(fill="x", pady=(6, 0))

        tk.Label(keys_frame, text="Ledger private key", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=0, padx=6, pady=4, sticky="w"
        )
        self.ledger_private_entry = tk.Entry(keys_frame, width=38)
        self.ledger_private_entry.grid(row=0, column=1, padx=6, pady=4, sticky="w")
        self.ledger_private_entry.insert(0, LEDGER_PRIVATE_KEY)
        tk.Button(
            keys_frame,
            text="Browse",
            command=lambda: self._pick_file(self.ledger_private_entry),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        ).grid(row=0, column=2, padx=6, pady=4)

        tk.Label(keys_frame, text="Ledger public key", fg="#cbd5e1", bg="#0f1115").grid(
            row=1, column=0, padx=6, pady=4, sticky="w"
        )
        self.ledger_public_entry = tk.Entry(keys_frame, width=38)
        self.ledger_public_entry.grid(row=1, column=1, padx=6, pady=4, sticky="w")
        self.ledger_public_entry.insert(0, LEDGER_PUBLIC_KEY)
        tk.Button(
            keys_frame,
            text="Browse",
            command=lambda: self._pick_file(self.ledger_public_entry),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        ).grid(row=1, column=2, padx=6, pady=4)

        tk.Label(keys_frame, text="Issuer ID", fg="#cbd5e1", bg="#0f1115").grid(
            row=2, column=0, padx=6, pady=4, sticky="w"
        )
        self.issuer_id_entry = tk.Entry(keys_frame, width=38)
        self.issuer_id_entry.grid(row=2, column=1, padx=6, pady=4, sticky="w")
        self.issuer_id_entry.insert(0, "origin-authority")
        tk.Button(
            keys_frame,
            text="Init ledger",
            command=self.init_ledger,
            bg="#0b1220",
            fg="#e2e8f0",
            padx=8,
            pady=2,
            relief="flat",
        ).grid(row=2, column=2, padx=6, pady=4)

        tk.Label(keys_frame, text="License private key", fg="#cbd5e1", bg="#0f1115").grid(
            row=3, column=0, padx=6, pady=4, sticky="w"
        )
        self.license_private_entry = tk.Entry(keys_frame, width=38)
        self.license_private_entry.grid(row=3, column=1, padx=6, pady=4, sticky="w")
        self.license_private_entry.insert(0, LICENSE_PRIVATE_KEY)
        tk.Button(
            keys_frame,
            text="Browse",
            command=lambda: self._pick_file(self.license_private_entry),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        ).grid(row=3, column=2, padx=6, pady=4)

        tk.Label(keys_frame, text="License public key", fg="#cbd5e1", bg="#0f1115").grid(
            row=4, column=0, padx=6, pady=4, sticky="w"
        )
        self.license_public_entry = tk.Entry(keys_frame, width=38)
        self.license_public_entry.grid(row=4, column=1, padx=6, pady=4, sticky="w")
        self.license_public_entry.insert(0, LICENSE_PUBLIC_KEY)
        tk.Button(
            keys_frame,
            text="Browse",
            command=lambda: self._pick_file(self.license_public_entry),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        ).grid(row=4, column=2, padx=6, pady=4)

        tk.Button(
            keys_frame,
            text="Generate issuer keys",
            command=self.generate_issuer_keys,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=8,
            pady=2,
            relief="flat",
        ).grid(row=5, column=1, padx=6, pady=(8, 4), sticky="w")

        ban_frame = tk.Frame(self.authority_frame, bg="#0f1115")
        ban_frame.pack(fill="x", pady=(8, 0))

        tk.Label(ban_frame, text="User ID", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=0, padx=6, pady=4, sticky="w"
        )
        self.user_id_entry = tk.Entry(ban_frame, width=28)
        self.user_id_entry.grid(row=0, column=1, padx=6, pady=4, sticky="w")

        tk.Label(ban_frame, text="License ID", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=2, padx=6, pady=4, sticky="w"
        )
        self.license_id_entry = tk.Entry(ban_frame, width=28)
        self.license_id_entry.grid(row=0, column=3, padx=6, pady=4, sticky="w")

        tk.Label(ban_frame, text="Reason", fg="#cbd5e1", bg="#0f1115").grid(
            row=1, column=0, padx=6, pady=4, sticky="w"
        )
        self.reason_entry = tk.Entry(ban_frame, width=28)
        self.reason_entry.grid(row=1, column=1, padx=6, pady=4, sticky="w")
        self.reason_entry.insert(0, "Policy violation")

        tk.Button(
            ban_frame,
            text="Revoke by license",
            command=self.revoke_by_license,
            bg="#ef4444",
            fg="#0f1115",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=1, column=2, padx=6, pady=4)

        tk.Button(
            ban_frame,
            text="Revoke by user",
            command=self.revoke_by_user,
            bg="#ef4444",
            fg="#0f1115",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=1, column=3, padx=6, pady=4)

        tk.Button(
            ban_frame,
            text="Add ban",
            command=self.add_ban,
            bg="#7c2d12",
            fg="#fef3c7",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=0, column=4, padx=6, pady=4)

        tk.Button(
            ban_frame,
            text="Remove ban",
            command=self.remove_ban,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=1, column=4, padx=6, pady=4)

        coupon_frame = tk.Frame(self.authority_frame, bg="#0f1115")
        coupon_frame.pack(fill="x", pady=(8, 0))

        tk.Label(coupon_frame, text="Coupon code", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=0, padx=6, pady=4, sticky="w"
        )
        self.coupon_code_entry = tk.Entry(coupon_frame, width=18)
        self.coupon_code_entry.grid(row=0, column=1, padx=6, pady=4, sticky="w")

        tk.Label(coupon_frame, text="Days", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=2, padx=6, pady=4, sticky="w"
        )
        self.coupon_days_entry = tk.Entry(coupon_frame, width=6)
        self.coupon_days_entry.grid(row=0, column=3, padx=6, pady=4, sticky="w")
        self.coupon_days_entry.insert(0, "30")

        tk.Label(coupon_frame, text="Plan", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=4, padx=6, pady=4, sticky="w"
        )
        self.coupon_plan_entry = tk.Entry(coupon_frame, width=12)
        self.coupon_plan_entry.grid(row=0, column=5, padx=6, pady=4, sticky="w")
        self.coupon_plan_entry.insert(0, DEFAULT_PLAN)

        tk.Button(
            coupon_frame,
            text="Add coupon",
            command=self.add_coupon,
            bg="#22c55e",
            fg="#0f1115",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=0, column=6, padx=6, pady=4)

        license_frame = tk.Frame(self.authority_frame, bg="#0f1115")
        license_frame.pack(fill="x", pady=(8, 0))

        tk.Label(license_frame, text="Issue license for", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=0, padx=6, pady=4, sticky="w"
        )
        self.issue_user_entry = tk.Entry(license_frame, width=28)
        self.issue_user_entry.grid(row=0, column=1, padx=6, pady=4, sticky="w")

        tk.Label(license_frame, text="Days", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=2, padx=6, pady=4, sticky="w"
        )
        self.issue_days_entry = tk.Entry(license_frame, width=6)
        self.issue_days_entry.grid(row=0, column=3, padx=6, pady=4, sticky="w")
        self.issue_days_entry.insert(0, str(DEFAULT_PLAN_DAYS))

        tk.Label(license_frame, text="Plan", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=4, padx=6, pady=4, sticky="w"
        )
        self.issue_plan_entry = tk.Entry(license_frame, width=12)
        self.issue_plan_entry.grid(row=0, column=5, padx=6, pady=4, sticky="w")
        self.issue_plan_entry.insert(0, DEFAULT_PLAN)

        tk.Button(
            license_frame,
            text="Issue license",
            command=self.issue_license,
            bg="#22c55e",
            fg="#0f1115",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=0, column=6, padx=6, pady=4)

        node_frame = tk.Frame(self.authority_frame, bg="#0f1115")
        node_frame.pack(fill="x", pady=(8, 0))

        tk.Label(node_frame, text="Promotion cert", fg="#cbd5e1", bg="#0f1115").grid(
            row=0, column=0, padx=6, pady=4, sticky="w"
        )
        self.promotion_cert_entry = tk.Entry(node_frame, width=40)
        self.promotion_cert_entry.grid(row=0, column=1, padx=6, pady=4, sticky="w")
        tk.Button(
            node_frame,
            text="Browse",
            command=lambda: self._pick_file(self.promotion_cert_entry),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        ).grid(row=0, column=2, padx=6, pady=4)
        tk.Button(
            node_frame,
            text="Add promotion",
            command=self.add_node_promotion_entry,
            bg="#22c55e",
            fg="#0f1115",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=0, column=3, padx=6, pady=4)

        tk.Label(node_frame, text="Demotion cert", fg="#cbd5e1", bg="#0f1115").grid(
            row=1, column=0, padx=6, pady=4, sticky="w"
        )
        self.demotion_cert_entry = tk.Entry(node_frame, width=40)
        self.demotion_cert_entry.grid(row=1, column=1, padx=6, pady=4, sticky="w")
        tk.Button(
            node_frame,
            text="Browse",
            command=lambda: self._pick_file(self.demotion_cert_entry),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        ).grid(row=1, column=2, padx=6, pady=4)
        tk.Button(
            node_frame,
            text="Add demotion",
            command=self.add_node_demotion_entry,
            bg="#ef4444",
            fg="#0f1115",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=1, column=3, padx=6, pady=4)

        tk.Label(node_frame, text="Revoke node", fg="#cbd5e1", bg="#0f1115").grid(
            row=2, column=0, padx=6, pady=4, sticky="w"
        )
        self.revoke_node_entry = tk.Entry(node_frame, width=28)
        self.revoke_node_entry.grid(row=2, column=1, padx=6, pady=4, sticky="w")
        tk.Label(node_frame, text="Reason", fg="#cbd5e1", bg="#0f1115").grid(
            row=2, column=2, padx=6, pady=4, sticky="w"
        )
        self.revoke_node_reason_entry = tk.Entry(node_frame, width=18)
        self.revoke_node_reason_entry.grid(row=2, column=3, padx=6, pady=4, sticky="w")
        tk.Button(
            node_frame,
            text="Add revocation",
            command=self.add_node_revocation_entry,
            bg="#7c2d12",
            fg="#fef3c7",
            padx=8,
            pady=4,
            relief="flat",
        ).grid(row=2, column=4, padx=6, pady=4)


        toggle_frame = tk.Frame(self, bg="#0f1115")
        toggle_frame.pack(fill="x", padx=12, pady=(0, 4))

        self.output_toggle_btn = tk.Button(
            toggle_frame,
            text="Hide output",
            command=self._toggle_output_panel,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        )
        self.output_toggle_btn.pack(side="left")

        self.output_frame = tk.Frame(self, bg="#0f1115")
        self.output_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.output = tk.Text(
            self.output_frame,
            bg="#111827",
            fg="#e5e7eb",
            wrap="word",
        )
        self.output.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(self.output_frame, orient="vertical", command=self.output.yview)
        scrollbar.pack(side="right", fill="y")
        self.output.configure(yscrollcommand=scrollbar.set)

        self.authority_state = self._load_authority_state()

    def _load_authority_state(self) -> dict[str, Any]:
        if not AUTH_STATE_PATH.exists():
            return {"banned_users": [], "coupons": []}
        try:
            return json.loads(AUTH_STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {"banned_users": [], "coupons": []}

    def _save_authority_state(self) -> None:
        AUTH_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        AUTH_STATE_PATH.write_text(json.dumps(self.authority_state, indent=2, sort_keys=True), encoding="utf-8")

    def _read_public_key_pem(self, path: str) -> bytes:
        return Path(path).read_bytes()

    def _pick_file(self, entry: tk.Entry) -> None:
        path = filedialog.askopenfilename(title="Select file")
        if not path:
            return
        entry.delete(0, tk.END)
        entry.insert(0, path)

    def _ledger_paths(self) -> tuple[str, str, str]:
        ledger_path = self.ledger_entry.get().strip()
        private_key = self.ledger_private_entry.get().strip()
        public_key = self.ledger_public_entry.get().strip()
        if not ledger_path or not private_key or not public_key:
            raise RuntimeError("Ledger path and keys are required.")
        if not Path(private_key).exists() or not Path(public_key).exists():
            raise RuntimeError("Ledger key file not found. Use Browse to select keys.")
        return ledger_path, private_key, public_key

    def _node_ledger_paths(self) -> tuple[str, str, str]:
        ledger_path = self.node_ledger_entry.get().strip()
        private_key = self.ledger_private_entry.get().strip()
        public_key = self.ledger_public_entry.get().strip()
        if not ledger_path or not private_key or not public_key:
            raise RuntimeError("Node ledger path and keys are required.")
        if not Path(private_key).exists() or not Path(public_key).exists():
            raise RuntimeError("Node ledger key file not found. Use Browse to select keys.")
        return ledger_path, private_key, public_key

    def _bootstrap_path(self) -> Path:
        path = Path(self.bootstrap_entry.get().strip())
        if not path:
            raise RuntimeError("Bootstrap path is required.")
        return path

    def _governance_config_path(self) -> Path:
        path = Path(self.governance_config_entry.get().strip())
        if not path:
            raise RuntimeError("Governance config path is required.")
        return path

    def _license_key_paths(self) -> tuple[str, str]:
        private_key = self.license_private_entry.get().strip()
        public_key = self.license_public_entry.get().strip()
        if not private_key or not public_key:
            raise RuntimeError("License keys are required.")
        if not Path(private_key).exists() or not Path(public_key).exists():
            raise RuntimeError("License key file not found. Use Browse or Generate issuer keys.")
        return private_key, public_key

    def _latest_license_id(self, user_id: str) -> str | None:
        index_path = LICENSE_INDEX_PATH
        if not index_path.exists():
            return None
        lines = index_path.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("user_id") == user_id:
                return entry.get("license_id")
        return None

    def init_ledger(self) -> None:
        issuer_id = self.issuer_id_entry.get().strip()
        if not issuer_id:
            messagebox.showwarning("Ledger", "Enter an issuer ID.")
            return
        try:
            ledger_path, private_key, public_key = self._ledger_paths()
            ledger = build_license_ledger(issuer_id)
            signer = load_private_key(Path(private_key))
            signature = sign_license_ledger(ledger, signer)
            public_key_pem = self._read_public_key_pem(public_key)
            write_license_ledger_file(ledger, signature, public_key_pem, Path(ledger_path))
            self._write_output({"status": "ledger_initialized", "ledger": ledger_path})
        except Exception as exc:
            messagebox.showerror("Ledger", str(exc))

    def generate_issuer_keys(self) -> None:
        output_dir = DEFAULT_ISSUER_DIR
        if output_dir.exists() and any(output_dir.iterdir()):
            if not messagebox.askyesno(
                "Issuer keys",
                "Issuer keys already exist. Overwrite them?",
            ):
                return
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            keypair = generate_keypair()
            private_path, public_path = save_keypair(keypair, output_dir)
            self.ledger_private_entry.delete(0, tk.END)
            self.ledger_private_entry.insert(0, str(private_path))
            self.ledger_public_entry.delete(0, tk.END)
            self.ledger_public_entry.insert(0, str(public_path))
            self.license_private_entry.delete(0, tk.END)
            self.license_private_entry.insert(0, str(private_path))
            self.license_public_entry.delete(0, tk.END)
            self.license_public_entry.insert(0, str(public_path))
            self._write_output(
                {
                    "status": "issuer_keys_generated",
                    "private_key": str(private_path),
                    "public_key": str(public_path),
                }
            )
        except Exception as exc:
            messagebox.showerror("Issuer keys", str(exc))

    def refresh_metrics(self) -> None:
        path = Path(self.event_log_entry.get().strip())
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")
        totals = {
            "total_events": 0,
            "payments": 0,
            "cancellations": 0,
            "errors": 0,
            "revenue": 0.0,
        }
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                totals["total_events"] += 1
                event_type = entry.get("event_type", "")
                if event_type == "payment":
                    totals["payments"] += 1
                elif event_type == "cancel":
                    totals["cancellations"] += 1
                elif event_type == "error":
                    totals["errors"] += 1
                amount = entry.get("amount")
                if isinstance(amount, (int, float)):
                    totals["revenue"] += float(amount)
        except Exception as exc:
            messagebox.showerror("Metrics", str(exc))
            return
        self._write_output(totals)

    def export_ledger(self) -> None:
        ledger_path = Path(self.ledger_entry.get().strip())
        if not ledger_path.exists():
            messagebox.showwarning("Ledger", "Ledger file not found.")
            return
        output_dir = filedialog.askdirectory(title="Choose export folder")
        if not output_dir:
            return
        target = Path(output_dir) / ledger_path.name
        target.write_bytes(ledger_path.read_bytes())
        messagebox.showinfo("Ledger", f"Ledger exported to {target}")

    def copy_ledger_cid(self) -> None:
        ledger_path = Path(self.ledger_entry.get().strip())
        if not ledger_path.exists():
            messagebox.showwarning("Ledger", "Ledger file not found.")
            return
        digest = hashlib.sha256(ledger_path.read_bytes()).hexdigest()
        cid = f"sha256:{digest}"
        self.clipboard_clear()
        self.clipboard_append(cid)
        self._write_output({"ledger_cid": cid})

    def init_node_ledger(self) -> None:
        issuer_id = self.issuer_id_entry.get().strip()
        if not issuer_id:
            messagebox.showwarning("Node ledger", "Enter an issuer ID.")
            return
        try:
            ledger_path, private_key, public_key = self._node_ledger_paths()
            ledger = build_node_ledger(issuer_id)
            signer = load_private_key(Path(private_key))
            signature = sign_node_ledger(ledger, signer)
            public_key_pem = self._read_public_key_pem(public_key)
            write_node_ledger_file(ledger, signature, public_key_pem, ledger_path)
            self._write_output({"status": "node_ledger_initialized", "ledger": ledger_path})
        except Exception as exc:
            messagebox.showerror("Node ledger", str(exc))

    def copy_node_ledger_cid(self) -> None:
        ledger_path = Path(self.node_ledger_entry.get().strip())
        if not ledger_path.exists():
            messagebox.showwarning("Node ledger", "Node ledger file not found.")
            return
        digest = hashlib.sha256(ledger_path.read_bytes()).hexdigest()
        cid = f"sha256:{digest}"
        self.clipboard_clear()
        self.clipboard_append(cid)
        self._write_output({"node_ledger_cid": cid})

    def update_bootstrap(self) -> None:
        try:
            bootstrap_path = self._bootstrap_path()
            if bootstrap_path.exists():
                confirm = messagebox.askyesno(
                    "Bootstrap",
                    "Bootstrap file already exists. Overwrite it?",
                )
                if not confirm:
                    return
            data: dict[str, Any] = {}
            if bootstrap_path.exists():
                data = json.loads(bootstrap_path.read_text(encoding="utf-8"))
            else:
                data = {
                    "ledger_cid": "",
                    "node_endpoints": [],
                    "ipfs_gateways": [],
                    "governance_ledger_cid": "",
                    "governance_node_endpoints": [],
                    "governance_ipfs_gateways": [],
                }

            ledger_path = Path(self.ledger_entry.get().strip())
            if ledger_path.exists():
                data["ledger_cid"] = f"sha256:{hashlib.sha256(ledger_path.read_bytes()).hexdigest()}"
            node_ledger_path = Path(self.node_ledger_entry.get().strip())
            if node_ledger_path.exists():
                data["governance_ledger_cid"] = f"sha256:{hashlib.sha256(node_ledger_path.read_bytes()).hexdigest()}"

            if self.governance_config:
                data["governance_node_endpoints"] = list(self.governance_config.get("nodes", []))
                data["governance_ipfs_gateways"] = list(self.governance_config.get("gateways", []))

            bootstrap_path.parent.mkdir(parents=True, exist_ok=True)
            bootstrap_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            self._write_output({"status": "bootstrap_updated", "path": str(bootstrap_path), "data": data})
        except Exception as exc:
            messagebox.showerror("Bootstrap", str(exc))

    def refresh_governance_config(self) -> None:
        try:
            config_path = self._governance_config_path()
            if not config_path.exists():
                messagebox.showwarning("Governance config", "Config file not found.")
                return
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            nodes = payload.get("nodes")
            gateways = payload.get("gateways")
            if not isinstance(nodes, list) or not isinstance(gateways, list):
                messagebox.showwarning(
                    "Governance config",
                    "Config must include nodes: [...] and gateways: [...].",
                )
                return
            self.governance_config = {"nodes": nodes, "gateways": gateways}
            self._write_output({"status": "governance_config_loaded", **self.governance_config})
        except Exception as exc:
            messagebox.showwarning("Governance config", str(exc))

    def open_governance_config(self) -> None:
        try:
            config_path = self._governance_config_path()
            if not config_path.exists():
                messagebox.showwarning("Governance config", "Config file not found.")
                return
            if sys.platform.startswith("win"):
                os.startfile(config_path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f"open \"{config_path}\"")
            else:
                os.system(f"xdg-open \"{config_path}\"")
        except Exception as exc:
            messagebox.showwarning("Governance config", str(exc))

    def open_bootstrap(self) -> None:
        try:
            bootstrap_path = self._bootstrap_path()
            if not bootstrap_path.exists():
                messagebox.showwarning("Bootstrap", "Bootstrap file not found.")
                return
            if sys.platform.startswith("win"):
                os.startfile(bootstrap_path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                os.system(f"open \"{bootstrap_path}\"")
            else:
                os.system(f"xdg-open \"{bootstrap_path}\"")
        except Exception as exc:
            messagebox.showwarning("Bootstrap", str(exc))

    def add_node_promotion_entry(self) -> None:
        cert_path = self.promotion_cert_entry.get().strip()
        if not cert_path:
            messagebox.showwarning("Node ledger", "Select a promotion certificate.")
            return
        try:
            payload = json.loads(Path(cert_path).read_text(encoding="utf-8"))
            approvals = tuple(
                payload.get("approvals", [])
            )
            certificate = NodePromotionCertificate(
                node_key=payload["node_key"],
                request_hash=payload["request_hash"],
                approvals_required=int(payload["approvals_required"]),
                approvals=tuple(
                    NodeAuthoritySignature(
                        authority_key=item["authority_key"],
                        signature=item["signature"],
                        signed_at=item["signed_at"],
                    )
                    for item in approvals
                ),
                issued_at=payload["issued_at"],
                origin_schema=payload.get("origin_schema", "1.0"),
                signature_algorithm=payload.get("signature_algorithm", "ed25519"),
                origin_version=payload.get("origin_version"),
            )
            ledger_path, private_key, public_key = self._node_ledger_paths()
            ledger, _, _ = read_node_ledger_file(ledger_path)
            ledger = add_node_ledger_entry(ledger, build_promotion_entry(certificate))
            signature = sign_node_ledger(ledger, load_private_key(Path(private_key)))
            write_node_ledger_file(ledger, signature, Path(public_key).read_bytes(), ledger_path)
            self._write_output({"status": "node_promotion_added", "node_key": certificate.node_key})
        except Exception as exc:
            messagebox.showerror("Node ledger", str(exc))

    def add_node_demotion_entry(self) -> None:
        cert_path = self.demotion_cert_entry.get().strip()
        if not cert_path:
            messagebox.showwarning("Node ledger", "Select a demotion certificate.")
            return
        try:
            payload = json.loads(Path(cert_path).read_text(encoding="utf-8"))
            approvals = tuple(
                payload.get("approvals", [])
            )
            certificate = NodeDemotionCertificate(
                node_key=payload["node_key"],
                reason=payload["reason"],
                request_hash=payload.get("request_hash"),
                approvals_required=int(payload["approvals_required"]),
                approvals=tuple(
                    NodeAuthoritySignature(
                        authority_key=item["authority_key"],
                        signature=item["signature"],
                        signed_at=item["signed_at"],
                    )
                    for item in approvals
                ),
                issued_at=payload["issued_at"],
                origin_schema=payload.get("origin_schema", "1.0"),
                signature_algorithm=payload.get("signature_algorithm", "ed25519"),
                origin_version=payload.get("origin_version"),
            )
            ledger_path, private_key, public_key = self._node_ledger_paths()
            ledger, _, _ = read_node_ledger_file(ledger_path)
            ledger = add_node_ledger_entry(ledger, build_demotion_entry(certificate))
            signature = sign_node_ledger(ledger, load_private_key(Path(private_key)))
            write_node_ledger_file(ledger, signature, Path(public_key).read_bytes(), ledger_path)
            self._write_output({"status": "node_demotion_added", "node_key": certificate.node_key})
        except Exception as exc:
            messagebox.showerror("Node ledger", str(exc))

    def add_node_revocation_entry(self) -> None:
        node_key = self.revoke_node_entry.get().strip()
        if not node_key:
            messagebox.showwarning("Node ledger", "Enter a node key.")
            return
        reason = self.revoke_node_reason_entry.get().strip() or "policy_violation"
        try:
            ledger_path, private_key, public_key = self._node_ledger_paths()
            ledger, _, _ = read_node_ledger_file(ledger_path)
            ledger = add_node_ledger_entry(ledger, build_revocation_entry(node_key, reason))
            signature = sign_node_ledger(ledger, load_private_key(Path(private_key)))
            write_node_ledger_file(ledger, signature, Path(public_key).read_bytes(), ledger_path)
            self._write_output({"status": "node_revoked", "node_key": node_key, "reason": reason})
        except Exception as exc:
            messagebox.showerror("Node ledger", str(exc))

    def revoke_by_license(self) -> None:
        license_id = self.license_id_entry.get().strip()
        if not license_id:
            messagebox.showwarning("Ledger", "Enter a license ID.")
            return
        reason = self.reason_entry.get().strip() or "Policy violation"
        try:
            ledger_path, private_key, public_key = self._ledger_paths()
            ledger_file = Path(ledger_path)
            if not ledger_file.exists():
                messagebox.showwarning("Ledger", "Ledger file not found. Initialize it first.")
                return
            ledger, _, _ = read_license_ledger_file(ledger_file)
            entry = LicenseLedgerEntry(
                license_id=license_id,
                revoked_at=datetime.now(timezone.utc).isoformat(),
                reason=reason,
            )
            updated = add_license_ledger_entry(ledger, entry)
            signer = load_private_key(Path(private_key))
            signature = sign_license_ledger(updated, signer)
            public_key_pem = self._read_public_key_pem(public_key)
            write_license_ledger_file(updated, signature, public_key_pem, ledger_file)
            self._write_output({"status": "revoked", "license_id": license_id, "reason": reason})
        except Exception as exc:
            messagebox.showerror("Ledger", str(exc))

    def revoke_by_user(self) -> None:
        user_id = self.user_id_entry.get().strip()
        if not user_id:
            messagebox.showwarning("Ledger", "Enter a user ID.")
            return
        license_id = self._latest_license_id(user_id)
        if not license_id:
            messagebox.showwarning("Ledger", "No license found for user.")
            return
        self.license_id_entry.delete(0, tk.END)
        self.license_id_entry.insert(0, license_id)
        self.revoke_by_license()

    def add_coupon(self) -> None:
        code = self.coupon_code_entry.get().strip()
        if not code:
            messagebox.showwarning("Coupons", "Enter a coupon code.")
            return
        try:
            days = int(self.coupon_days_entry.get().strip() or DEFAULT_PLAN_DAYS)
        except ValueError:
            messagebox.showwarning("Coupons", "Days must be a number.")
            return
        plan = self.coupon_plan_entry.get().strip() or DEFAULT_PLAN
        coupon = {
            "code": code,
            "days": days,
            "plan": plan,
            "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        coupons = self.authority_state.get("coupons", [])
        coupons = [item for item in coupons if item.get("code") != code]
        coupons.append(coupon)
        self.authority_state["coupons"] = coupons
        self._save_authority_state()
        self._write_output({"status": "coupon_added", "coupon": coupon})

    def add_ban(self) -> None:
        user_id = self.user_id_entry.get().strip()
        if not user_id:
            messagebox.showwarning("Ban", "Enter a user ID.")
            return
        reason = self.reason_entry.get().strip() or "Policy violation"
        banned = self.authority_state.get("banned_users", [])
        banned = [item for item in banned if item.get("user_id") != user_id]
        banned.append(
            {
                "user_id": user_id,
                "reason": reason,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        self.authority_state["banned_users"] = banned
        self._save_authority_state()
        self._write_output({"status": "user_banned", "user_id": user_id, "reason": reason})

    def remove_ban(self) -> None:
        user_id = self.user_id_entry.get().strip()
        if not user_id:
            messagebox.showwarning("Ban", "Enter a user ID.")
            return
        banned = self.authority_state.get("banned_users", [])
        banned = [item for item in banned if item.get("user_id") != user_id]
        self.authority_state["banned_users"] = banned
        self._save_authority_state()
        self._write_output({"status": "ban_removed", "user_id": user_id})

    def issue_license(self) -> None:
        user_id = self.issue_user_entry.get().strip()
        if not user_id:
            messagebox.showwarning("License", "Enter a user ID.")
            return
        try:
            days = int(self.issue_days_entry.get().strip() or DEFAULT_PLAN_DAYS)
        except ValueError:
            messagebox.showwarning("License", "Days must be a number.")
            return
        plan = self.issue_plan_entry.get().strip() or DEFAULT_PLAN
        expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
        LICENSE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        output_path = LICENSE_OUTPUT_DIR / f"{user_id.replace('@', '_')}.originlicense"
        try:
            private_key, public_key = self._license_key_paths()
            license_obj = build_license(user_id=user_id, plan=plan, expires_at=expires_at)
            signer = load_private_key(Path(private_key))
            signature = sign_license(license_obj, signer)
            public_key_pem = self._read_public_key_pem(public_key)
            write_license_file(license_obj, signature, public_key_pem, output_path)
            LICENSE_INDEX_PATH.write_text(
                (LICENSE_INDEX_PATH.read_text(encoding="utf-8") if LICENSE_INDEX_PATH.exists() else "")
                + json.dumps(
                    {
                        "user_id": user_id,
                        "license_id": license_obj.license_id,
                        "license_path": str(output_path),
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            self._write_output({"status": "issued", "user_id": user_id, "license": str(output_path)})
        except Exception as exc:
            messagebox.showerror("License", str(exc))

    def _write_output(self, payload: dict[str, Any]) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", json.dumps(payload, indent=2, sort_keys=True))
        self.output.configure(state="disabled")

    def _toggle_output_panel(self) -> None:
        if self.output_frame is None:
            return
        if self.output_visible:
            self.output_frame.pack_forget()
            self.output_toggle_btn.config(text="Show output")
            self.output_visible = False
            if self.authority_frame is not None:
                self.authority_frame.pack_configure(fill="both", expand=True)
        else:
            self.output_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))
            self.output_toggle_btn.config(text="Hide output")
            self.output_visible = True
            if self.authority_frame is not None:
                self.authority_frame.pack_configure(fill="both", expand=True)


if __name__ == "__main__":
    app = PayPalAdminApp()
    app.mainloop()
