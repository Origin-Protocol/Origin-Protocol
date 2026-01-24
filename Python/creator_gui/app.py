from __future__ import annotations

import sys
import os
import json
import shutil
import subprocess
import hashlib
import platform
import uuid
import webbrowser
import base64
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from zipfile import ZipFile
import tkinter as tk
from tkinter import filedialog, messagebox
from urllib import request as urlrequest

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_BACKEND_AVAILABLE = True
except Exception:
    TkinterDnD = None  # type: ignore[assignment]
    DND_FILES = "DND_Files"
    DND_BACKEND_AVAILABLE = False

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from origin_protocol.embed import create_sealed_bundle
from origin_protocol.container import build_sidecar_from_bundle, extract_origin_payload, validate_origin_payload
from origin_protocol.keys import generate_keypair, save_keypair, load_private_key, load_public_key_bytes
from origin_protocol.manifest import build_manifest
from origin_protocol.reasons import REJECTION_REASONS
from origin_protocol.policy import PolicyProfile, build_policy_for_profile, verify_sealed_bundle_with_policy
from origin_protocol.verify import verify_sealed_bundle_detailed
from origin_protocol.license import read_license_file, read_license_ledger_file, validate_license, verify_license, verify_license_ledger
from origin_protocol.nodes import (
    compute_authority_set,
    node_ledger_from_bytes,
    read_node_ledger_file,
    verify_node_ledger,
)

APP_DIR = Path.home() / ".origin_protocol"
KEYS_DIR = APP_DIR / "keys"
STATE_PATH = APP_DIR / "state.json"
AUDIT_LOG_PATH = APP_DIR / "audit_log.jsonl"
ASSET_REGISTRY_PATH = APP_DIR / "asset_registry.jsonl"
LICENSE_PATH = APP_DIR / "membership.originlicense"
LICENSE_LEDGER_PATH = APP_DIR / "license_ledger.json"
NODE_GOVERNANCE_PATH = APP_DIR / "node_ledger.json"
NODE_METRICS_PATH = APP_DIR / "node_metrics.json"
PAYMENT_LINK = os.environ.get("ORIGIN_PAYMENT_LINK", "https://www.paypal.com/ncp/payment/XMK7VEL6FGHTS")
OWNER_OVERRIDE_PATH = APP_DIR / "owner_override.json"
OWNER_PUBLIC_KEY_PATH = APP_DIR / "owner_public_key.ed25519"
OWNER_TOKEN_PATH = APP_DIR / "owner_token.json"
SAMPLE_MEDIA_PATH = APP_DIR / "sample.mp4"
FIXTURE_SAMPLE_PATH = ROOT / "tests" / "eval" / "fixtures" / "media" / "valid_media.mp4"
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".webp", ".gif", ".tiff", ".bmp"}
DEFAULT_NODE_ENDPOINTS = (
    os.environ.get("ORIGIN_LEDGER_NODES", "").split(",") if os.environ.get("ORIGIN_LEDGER_NODES") else []
)
DEFAULT_IPFS_GATEWAYS = (
    os.environ.get("ORIGIN_IPFS_GATEWAYS", "").split(",") if os.environ.get("ORIGIN_IPFS_GATEWAYS") else []
)
BOOTSTRAP_PATH = Path(__file__).resolve().parent / "ledger_bootstrap.json"


def ensure_keypair() -> tuple[Path, Path]:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_path = KEYS_DIR / "private_key.ed25519"
    public_path = KEYS_DIR / "public_key.ed25519"
    if private_path.exists() and public_path.exists():
        return private_path, public_path
    keypair = generate_keypair()
    return save_keypair(keypair, KEYS_DIR)


def human_reason(code: str | None) -> str:
    if not code:
        return "All checks passed."
    reason = REJECTION_REASONS.get(code)
    if reason:
        return reason.message
    return code


def device_fingerprint() -> str:
    raw = "|".join(
        [
            platform.system(),
            platform.release(),
            platform.machine(),
            platform.node(),
            str(uuid.getnode()),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def owner_override_enabled() -> bool:
    env_flag = os.environ.get("ORIGIN_OWNER_BYPASS", "").strip().lower()
    if env_flag in {"1", "true", "yes"}:
        return True
    if not OWNER_OVERRIDE_PATH.exists():
        return _owner_token_valid()
    try:
        payload = json.loads(OWNER_OVERRIDE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return _owner_token_valid()
    if not payload.get("enabled"):
        return _owner_token_valid()
    expected = payload.get("device_fingerprint")
    if expected and expected != device_fingerprint():
        return _owner_token_valid()
    return True


def _owner_token_valid() -> bool:
    if not OWNER_TOKEN_PATH.exists() or not OWNER_PUBLIC_KEY_PATH.exists():
        return False
    try:
        payload = json.loads(OWNER_TOKEN_PATH.read_text(encoding="utf-8"))
        token = payload.get("token", {})
        signature_b64 = payload.get("signature", "")
        signature = base64.b64decode(signature_b64)
        public_key = load_public_key_bytes(OWNER_PUBLIC_KEY_PATH.read_bytes())
        token_bytes = json.dumps(token, sort_keys=True, separators=(",", ":")).encode("utf-8")
        public_key.verify(signature, token_bytes)
    except Exception:
        return False
    expected = token.get("device_fingerprint")
    if expected and expected != device_fingerprint():
        return False
    expires_at = token.get("expires_at")
    if expires_at:
        try:
            if datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc):
                return False
        except ValueError:
            return False
    return True


BaseTk = (
    cast(type[tk.Tk], TkinterDnD.Tk)
    if DND_BACKEND_AVAILABLE and TkinterDnD is not None
    else tk.Tk
)


class CreatorApp(BaseTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Origin Protocol — Creator Companion")
        self.geometry("680x420")
        self.configure(bg="#0f1115")
        self.main_frame: tk.Frame | None = None
        self.onboarding_frame: tk.Frame | None = None
        self.paywall_frame: tk.Frame | None = None
        self.paywall_status: tk.Label | None = None
        self.membership_banner: tk.Label | None = None
        self.membership_controls: list[tk.Widget] = []
        self.preview_mode = False
        self.media_path: Path | None = None
        self.history: list[str] = []
        self._dnd_available = False
        self.include_creator_id = tk.BooleanVar(value=True)
        self.include_asset_id = tk.BooleanVar(value=True)
        self.include_platforms = tk.BooleanVar(value=True)
        self.include_key_id = tk.BooleanVar(value=True)
        self.large_text = tk.BooleanVar(value=False)
        self.high_contrast = tk.BooleanVar(value=False)
        self.institutional_mode = tk.BooleanVar(value=False)
        self.platform_var = tk.StringVar(value="Meta")
        self.profile_var = tk.StringVar(value=PolicyProfile.STANDARD)
        self.tooltip_label: tk.Label | None = None
        self._tooltip_after_id: str | None = None
        self.creator_card_label: tk.Label | None = None
        self.creator_card_meta: tk.Label | None = None
        self.creator_card_status: tk.Label | None = None
        self.creator_card_platform: tk.Label | None = None
        self.warning_label: tk.Label | None = None
        self.status_bar: tk.Label | None = None
        self._status_after_id: str | None = None
        self.source_creator_entry: tk.Entry | None = None
        self.source_asset_entry: tk.Entry | None = None
        self.relationship_entry: tk.Entry | None = None
        self.attestation_path: Path | None = None
        self.attestation_sig_path: Path | None = None
        self.trust_store_path: Path | None = None
        self.registry_path: Path | None = None
        self.revocation_path: Path | None = None

        self._build_ui()
        self._record_node_activity("app_launches")
        self._apply_bootstrap_defaults()
        self._refresh_node_governance()
        if self._show_paywall_if_needed():
            return
        self._maybe_show_onboarding()

    def _build_ui(self) -> None:
        self.main_frame = tk.Frame(self, bg="#0f1115")
        self.main_frame.pack(fill="both", expand=True)

        self.tooltip_label = tk.Label(
            self,
            text="",
            fg="#e5e7eb",
            bg="#111827",
            font=("Segoe UI", 9),
            padx=8,
            pady=4,
            relief="solid",
            bd=1,
        )
        self.tooltip_label.place_forget()

        title = tk.Label(
            self.main_frame,
            text="Protect your work with one click",
            fg="#e6e6e6",
            bg="#0f1115",
            font=("Segoe UI", 18, "bold"),
        )
        title.pack(pady=(24, 8))

        subtitle = tk.Label(
            self.main_frame,
            text="Choose a video or image, seal it, and verify before you share.",
            fg="#9aa4b2",
            bg="#0f1115",
            font=("Segoe UI", 11),
        )
        subtitle.pack(pady=(0, 16))

        self.membership_banner = tk.Label(
            self.main_frame,
            text="Preview mode: sealing and exports are disabled until membership is active.",
            fg="#f97316",
            bg="#0f1115",
            font=("Segoe UI", 9, "bold"),
        )
        self.membership_banner.pack_forget()

        self.drop_label = tk.Label(
            self.main_frame,
            text="Drag & drop a video or image here",
            fg="#94a3b8",
            bg="#0b1220",
            font=("Segoe UI", 10, "bold"),
            relief="ridge",
            bd=1,
            padx=10,
            pady=12,
        )
        self.drop_label.pack(pady=(0, 12), fill="x", padx=40)
        self._enable_drag_and_drop()

        frame = tk.Frame(self.main_frame, bg="#0f1115")
        frame.pack(pady=8)

        self.file_label = tk.Label(
            frame,
            text="No file selected",
            fg="#cbd5e1",
            bg="#0f1115",
            font=("Segoe UI", 10),
            width=60,
            anchor="w",
        )
        self.file_label.grid(row=0, column=0, padx=8)

        select_btn = tk.Button(
            frame,
            text="Choose File",
            command=self.select_file,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=12,
            pady=6,
            relief="flat",
        )
        select_btn.grid(row=0, column=1, padx=8)

        meta_frame = tk.Frame(self.main_frame, bg="#0f1115")
        meta_frame.pack(pady=8)

        creator_label = tk.Label(meta_frame, text="Creator ID", fg="#cbd5e1", bg="#0f1115")
        creator_label.grid(row=0, column=0, padx=8)
        self._attach_tooltip(creator_label, "Your creator identifier shown in the proof.")
        self.creator_entry = tk.Entry(meta_frame, width=28)
        self.creator_entry.insert(0, "creator-1")
        self.creator_entry.grid(row=0, column=1, padx=8)

        asset_label = tk.Label(meta_frame, text="Asset ID", fg="#cbd5e1", bg="#0f1115")
        asset_label.grid(row=0, column=2, padx=8)
        self._attach_tooltip(asset_label, "Your internal content ID for tracking and audits.")
        self.asset_entry = tk.Entry(meta_frame, width=28)
        self.asset_entry.insert(0, "asset-1")
        self.asset_entry.grid(row=0, column=3, padx=8)

        source_creator_label = tk.Label(meta_frame, text="Source creator", fg="#cbd5e1", bg="#0f1115")
        source_creator_label.grid(
            row=1,
            column=0,
            padx=8,
            pady=6,
            sticky="e",
        )
        self._attach_tooltip(source_creator_label, "Original creator if this is a remix or derivative.")
        self.source_creator_entry = tk.Entry(meta_frame, width=28)
        self.source_creator_entry.grid(row=1, column=1, padx=8, pady=6)

        source_asset_label = tk.Label(meta_frame, text="Source asset", fg="#cbd5e1", bg="#0f1115")
        source_asset_label.grid(
            row=1,
            column=2,
            padx=8,
            pady=6,
            sticky="e",
        )
        self._attach_tooltip(source_asset_label, "Original asset ID if this content is derived.")
        self.source_asset_entry = tk.Entry(meta_frame, width=28)
        self.source_asset_entry.grid(row=1, column=3, padx=8, pady=6)

        relationship_label = tk.Label(meta_frame, text="Relationship", fg="#cbd5e1", bg="#0f1115")
        relationship_label.grid(
            row=2,
            column=0,
            padx=8,
            pady=6,
            sticky="e",
        )
        self._attach_tooltip(relationship_label, "How this work relates to the source (Original, remix, edit, translation).")
        self.relationship_entry = tk.Entry(meta_frame, width=28)
        self.relationship_entry.insert(0, "remix")
        self.relationship_entry.grid(row=2, column=1, padx=8, pady=6)

        platforms_label = tk.Label(meta_frame, text="Intended platforms", fg="#cbd5e1", bg="#0f1115")
        platforms_label.grid(
            row=3,
            column=0,
            padx=8,
            pady=6,
            sticky="e",
        )
        self._attach_tooltip(platforms_label, "Optional list used by platform checks.")
        platforms_container = tk.Frame(meta_frame, bg="#0f1115")
        platforms_container.grid(row=3, column=1, padx=8, pady=6, sticky="w")
        self.platforms_list = tk.Listbox(
            platforms_container,
            height=4,
            selectmode="multiple",
            exportselection=False,
            bg="#111827",
            fg="#e5e7eb",
            highlightthickness=0,
            bd=0,
        )
        for option in (
            "Meta",
            "Instagram",
            "TikTok",
            "YouTube",
            "X (Twitter)",
            "Reddit",
            "Snapchat",
            "Twitch",
            "Vimeo",
            "Pinterest",
            "LinkedIn",
            "DaVinci",
        ):
            self.platforms_list.insert(tk.END, option)
        self.platforms_list.pack(side="left")
        platforms_scrollbar = tk.Scrollbar(platforms_container, orient="vertical", command=self.platforms_list.yview)
        platforms_scrollbar.pack(side="right", fill="y")
        self.platforms_list.configure(yscrollcommand=platforms_scrollbar.set)

        platform_actions = tk.Frame(meta_frame, bg="#0f1115")
        platform_actions.grid(row=3, column=2, columnspan=2, padx=8, pady=6, sticky="w")
        tk.Button(
            platform_actions,
            text="Select all",
            command=self._select_all_platforms,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=2,
            relief="flat",
        ).pack(side="left", padx=(0, 6))
        tk.Button(
            platform_actions,
            text="Clear",
            command=self._clear_platforms,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=2,
            relief="flat",
        ).pack(side="left")

        privacy_frame = tk.Frame(self.main_frame, bg="#0f1115")
        privacy_frame.pack(pady=6)

        tk.Checkbutton(
            privacy_frame,
            text="Include creator ID",
            variable=self.include_creator_id,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).grid(row=0, column=0, padx=8, sticky="w")
        tk.Checkbutton(
            privacy_frame,
            text="Include asset ID",
            variable=self.include_asset_id,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).grid(row=0, column=1, padx=8, sticky="w")
        tk.Checkbutton(
            privacy_frame,
            text="Include platforms",
            variable=self.include_platforms,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).grid(row=0, column=2, padx=8, sticky="w")
        key_id_check = tk.Checkbutton(
            privacy_frame,
            text="Include key ID",
            variable=self.include_key_id,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        )
        key_id_check.grid(row=0, column=3, padx=8, sticky="w")
        self._attach_tooltip(key_id_check, "Adds the signing key identifier to help verify the seal.")

        action_frame = tk.Frame(self.main_frame, bg="#0f1115")
        action_frame.pack(pady=12)

        self.seal_btn = tk.Button(
            action_frame,
            text="Seal Content",
            command=self.seal_content,
            bg="#22c55e",
            fg="#0f1115",
            padx=18,
            pady=8,
            relief="flat",
        )
        self.seal_btn.grid(row=0, column=0, padx=10)
        self._attach_tooltip(self.seal_btn, "Create and embed a signed seal for the selected file.")

        verify_btn = tk.Button(
            action_frame,
            text="Verify",
            command=self.verify_content,
            bg="#334155",
            fg="#e2e8f0",
            padx=18,
            pady=8,
            relief="flat",
        )
        verify_btn.grid(row=0, column=1, padx=10)
        self._attach_tooltip(verify_btn, "Check the file against its embedded Origin proof.")

        self.export_btn = tk.Button(
            action_frame,
            text="Export",
            command=self.export_artifacts,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=18,
            pady=8,
            relief="flat",
        )
        self.export_btn.grid(row=0, column=2, padx=10)
        self._attach_tooltip(self.export_btn, "Copy sealed artifacts to a folder you choose.")

        open_btn = tk.Button(
            action_frame,
            text="Open Folder",
            command=self.open_folder,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=18,
            pady=8,
            relief="flat",
        )
        open_btn.grid(row=0, column=3, padx=10)
        self._attach_tooltip(open_btn, "Open the folder that contains the selected file.")

        self.batch_btn = tk.Button(
            action_frame,
            text="Batch",
            command=self.batch_process,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=18,
            pady=8,
            relief="flat",
        )
        self.batch_btn.grid(row=0, column=4, padx=10)
        self._attach_tooltip(self.batch_btn, "Seal or verify a whole folder of videos at once.")

        copy_frame = tk.Frame(self.main_frame, bg="#0f1115")
        copy_frame.pack(pady=(4, 0))
        self.copy_bundle_btn = tk.Button(
            copy_frame,
            text="Copy bundle path",
            command=lambda: self.copy_artifact("bundle"),
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        )
        self.copy_bundle_btn.pack(side="left", padx=6)
        self._attach_tooltip(self.copy_bundle_btn, "Copy the sealed bundle path.")
        self.copy_sidecar_btn = tk.Button(
            copy_frame,
            text="Copy sidecar path",
            command=lambda: self.copy_artifact("sidecar"),
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        )
        self.copy_sidecar_btn.pack(side="left", padx=6)
        self._attach_tooltip(
            self.copy_sidecar_btn,
            "Copy the sidecar proof file (a small JSON) stored next to your media.",
        )

        self.publish_btn = tk.Button(
            copy_frame,
            text="Export publish pack",
            command=self.export_publish_pack,
            bg="#0f172a",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        )
        self.publish_btn.pack(side="left", padx=6)
        self._attach_tooltip(self.publish_btn, "Bundle + sidecar for sharing with platforms or partners.")

        self.compliance_btn = tk.Button(
            copy_frame,
            text="Export compliance pack",
            command=self.export_compliance_pack,
            bg="#0b1220",
            fg="#e2e8f0",
            padx=8,
            pady=4,
            relief="flat",
        )
        self.compliance_btn.pack(side="left", padx=6)
        self._attach_tooltip(
            self.compliance_btn,
            "Publish pack plus attestations, registries, and revocation evidence.",
        )

        panels = tk.Frame(self.main_frame, bg="#0f1115")
        panels.pack(pady=6, fill="both", expand=True)

        history_frame = tk.Frame(panels, bg="#0f1115")
        history_frame.pack(side="left", padx=12, pady=6, fill="both", expand=True)

        tk.Label(
            history_frame,
            text="Recent activity",
            fg="#cbd5e1",
            bg="#0f1115",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")

        self.history_list = tk.Listbox(
            history_frame,
            height=6,
            bg="#111827",
            fg="#e5e7eb",
            highlightthickness=0,
            bd=0,
        )
        self.history_list.pack(fill="both", expand=True, pady=6)

        preview_frame = tk.Frame(panels, bg="#0f1115")
        preview_frame.pack(side="left", padx=12, pady=6, fill="both", expand=True)

        preview_header = tk.Frame(preview_frame, bg="#0f1115")
        preview_header.pack(fill="x")
        tk.Label(
            preview_header,
            text="What platforms will see",
            fg="#cbd5e1",
            bg="#0f1115",
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", anchor="w")
        info_btn = tk.Button(
            preview_header,
            text="Why it matters",
            command=self._open_learn_more,
            bg="#0b1220",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        )
        info_btn.pack(side="right")

        self.preview_text = tk.Text(
            preview_frame,
            height=6,
            bg="#111827",
            fg="#e5e7eb",
            highlightthickness=0,
            bd=0,
            wrap="word",
        )
        self.preview_text.pack(fill="both", expand=True, pady=6)
        self.preview_text.insert("1.0", "Select a file to preview its metadata.")
        self.preview_text.configure(state="disabled")

        card_frame = tk.Frame(preview_frame, bg="#0b1220", bd=1, relief="ridge")
        card_frame.pack(fill="x", pady=(4, 8))
        self.creator_card_label = tk.Label(
            card_frame,
            text="Origin Protected",
            fg="#e2e8f0",
            bg="#0b1220",
            font=("Segoe UI", 10, "bold"),
        )
        self.creator_card_label.pack(anchor="w", padx=10, pady=(6, 2))
        self.creator_card_meta = tk.Label(
            card_frame,
            text="Original Creator: —",
            fg="#cbd5e1",
            bg="#0b1220",
            font=("Segoe UI", 9),
        )
        self.creator_card_meta.pack(anchor="w", padx=10)
        self.creator_card_status = tk.Label(
            card_frame,
            text="Status: Pending verification",
            fg="#94a3b8",
            bg="#0b1220",
            font=("Segoe UI", 9),
        )
        self.creator_card_status.pack(anchor="w", padx=10)
        self.creator_card_platform = tk.Label(
            card_frame,
            text="Platform view: —",
            fg="#94a3b8",
            bg="#0b1220",
            font=("Segoe UI", 9),
        )
        self.creator_card_platform.pack(anchor="w", padx=10, pady=(0, 6))

        self.warning_label = tk.Label(
            preview_frame,
            text="",
            fg="#f97316",
            bg="#0f1115",
            font=("Segoe UI", 9, "bold"),
        )
        self.warning_label.pack(anchor="w", pady=(0, 4))

        platform_frame = tk.Frame(preview_frame, bg="#0f1115")
        platform_frame.pack(fill="x", pady=(4, 0))

        tk.Label(
            platform_frame,
            text="Simulate platform:",
            fg="#cbd5e1",
            bg="#0f1115",
        ).pack(side="left", padx=(0, 6))

        platform_menu = tk.OptionMenu(
            platform_frame,
            self.platform_var,
            "Meta",
            "Instagram",
            "TikTok",
            "YouTube",
            "X (Twitter)",
            "Reddit",
            "Snapchat",
            "Twitch",
            "Vimeo",
            "Pinterest",
            "LinkedIn",
            "DaVinci",
        )
        platform_menu.config(bg="#1f2937", fg="#e2e8f0", bd=0, highlightthickness=0)
        platform_menu["menu"].config(bg="#1f2937", fg="#e2e8f0")
        platform_menu.pack(side="left", padx=(0, 6))

        profile_menu = tk.OptionMenu(
            platform_frame,
            self.profile_var,
            PolicyProfile.PERMISSIVE,
            PolicyProfile.STANDARD,
            PolicyProfile.STRICT,
        )
        profile_menu.config(bg="#1f2937", fg="#e2e8f0", bd=0, highlightthickness=0)
        profile_menu["menu"].config(bg="#1f2937", fg="#e2e8f0")
        profile_menu.pack(side="left", padx=(0, 6))

        self.run_check_btn = tk.Button(
            platform_frame,
            text="Run check",
            command=self.run_platform_check,
            bg="#111827",
            fg="#e2e8f0",
            padx=8,
            pady=2,
            relief="flat",
        )
        self.run_check_btn.pack(side="left")
        self._attach_tooltip(self.run_check_btn, "Simulate platform policy checks for the bundle.")

        self.platform_status = tk.Label(
            preview_frame,
            text="",
            fg="#94a3b8",
            bg="#0f1115",
            font=("Segoe UI", 9),
        )
        self.platform_status.pack(anchor="w", pady=(2, 0))

        policy_frame = tk.Frame(preview_frame, bg="#0f1115")
        policy_frame.pack(fill="x", pady=(4, 0))
        attestation_btn = tk.Button(
            policy_frame,
            text="Attestation",
            command=lambda: self._pick_policy_file("attestation"),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        )
        attestation_btn.pack(side="left", padx=(0, 6))
        self._attach_tooltip(attestation_btn, "Optional proof from a trusted issuer (like a certificate).")
        attestation_sig_btn = tk.Button(
            policy_frame,
            text="Attestation sig",
            command=lambda: self._pick_policy_file("attestation_sig"),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        )
        attestation_sig_btn.pack(side="left", padx=(0, 6))
        self._attach_tooltip(attestation_sig_btn, "Signature file that verifies the attestation.")
        trust_store_btn = tk.Button(
            policy_frame,
            text="Trust store",
            command=lambda: self._pick_policy_file("trust_store"),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        )
        trust_store_btn.pack(side="left", padx=(0, 6))
        self._attach_tooltip(trust_store_btn, "List of trusted issuers allowed to vouch for content.")
        registry_btn = tk.Button(
            policy_frame,
            text="Registry",
            command=lambda: self._pick_policy_file("registry"),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        )
        registry_btn.pack(side="left", padx=(0, 6))
        self._attach_tooltip(registry_btn, "Approved signing keys list (who is allowed to sign).")
        revocation_btn = tk.Button(
            policy_frame,
            text="Revocation",
            command=lambda: self._pick_policy_file("revocation"),
            bg="#111827",
            fg="#e2e8f0",
            padx=6,
            pady=2,
            relief="flat",
        )
        revocation_btn.pack(side="left")
        self._attach_tooltip(revocation_btn, "List of keys that should no longer be trusted.")

        indicator_frame = tk.Frame(self.main_frame, bg="#0f1115")
        indicator_frame.pack(pady=(4, 0))
        self.badge = tk.Label(
            indicator_frame,
            text="Status: Ready",
            fg="#e2e8f0",
            bg="#1f2937",
            font=("Segoe UI", 10, "bold"),
            padx=10,
            pady=4,
        )
        self.badge.pack(side="left", padx=8)

        self.status = tk.Label(
            indicator_frame,
            text="Ready",
            fg="#cbd5e1",
            bg="#0f1115",
            font=("Segoe UI", 10),
        )
        self.status.pack(side="left", padx=8)

        self.status_bar = tk.Label(
            self.main_frame,
            text="",
            fg="#94a3b8",
            bg="#0f1115",
            font=("Segoe UI", 9),
        )
        self.status_bar.pack(fill="x", padx=10)

        accessibility_frame = tk.Frame(self.main_frame, bg="#0f1115")
        accessibility_frame.pack(pady=(6, 10))
        tk.Checkbutton(
            accessibility_frame,
            text="Large text",
            variable=self.large_text,
            command=self.apply_accessibility,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).pack(side="left", padx=8)
        tk.Checkbutton(
            accessibility_frame,
            text="High contrast",
            variable=self.high_contrast,
            command=self.apply_accessibility,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).pack(side="left", padx=8)
        tk.Checkbutton(
            accessibility_frame,
            text="Institutional mode",
            variable=self.institutional_mode,
            command=self._update_preview,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).pack(side="left", padx=8)

        key_frame = tk.Frame(self.main_frame, bg="#0f1115")
        key_frame.pack(pady=(0, 6))

        key_btn = tk.Button(
            key_frame,
            text="Key Management",
            command=self.manage_keys,
            bg="#111827",
            fg="#e2e8f0",
            padx=12,
            pady=4,
            relief="flat",
        )
        key_btn.pack(side="left", padx=(0, 8))
        self._attach_tooltip(key_btn, "View or regenerate your signing keys.")

        library_btn = tk.Button(
            key_frame,
            text="Asset library",
            command=self._open_asset_library,
            bg="#0b1220",
            fg="#e2e8f0",
            padx=12,
            pady=4,
            relief="flat",
        )
        library_btn.pack(side="left")
        self._attach_tooltip(library_btn, "Review assets sealed in this app.")

        membership_btn = tk.Button(
            key_frame,
            text="Membership",
            command=self._open_membership,
            bg="#0b1220",
            fg="#e2e8f0",
            padx=12,
            pady=4,
            relief="flat",
        )
        membership_btn.pack(side="left", padx=(8, 0))
        self._attach_tooltip(membership_btn, "Load license and manage membership checks.")

        settings_btn = tk.Button(
            key_frame,
            text="Settings",
            command=self._open_settings,
            bg="#0b1220",
            fg="#e2e8f0",
            padx=12,
            pady=4,
            relief="flat",
        )
        settings_btn.pack(side="left", padx=(8, 0))
        self._attach_tooltip(settings_btn, "Adjust accessibility and UI defaults.")

        diagnostics_btn = tk.Button(
            key_frame,
            text="Diagnostics",
            command=self.export_diagnostics,
            bg="#0b1220",
            fg="#e2e8f0",
            padx=12,
            pady=4,
            relief="flat",
        )
        diagnostics_btn.pack(side="left", padx=(8, 0))
        self._attach_tooltip(diagnostics_btn, "Export logs and state for support.")

        self.membership_controls = [
            self.seal_btn,
            self.export_btn,
            self.batch_btn,
            self.copy_bundle_btn,
            self.copy_sidecar_btn,
            self.publish_btn,
            self.compliance_btn,
            self.run_check_btn,
        ]

    def _show_paywall_if_needed(self) -> bool:
        ok, message = self._enforce_membership()
        if ok:
            return False
        self._show_paywall(message)
        return True

    def _show_paywall(self, message: str | None = None) -> None:
        if self.main_frame is not None:
            self.main_frame.pack_forget()
        if self.onboarding_frame is not None:
            self.onboarding_frame.pack_forget()
        if self.paywall_frame is None:
            self.paywall_frame = tk.Frame(self, bg="#0f1115")

            tk.Label(
                self.paywall_frame,
                text="Membership required",
                fg="#e5e7eb",
                bg="#0f1115",
                font=("Segoe UI", 16, "bold"),
            ).pack(pady=(26, 8))

            tk.Label(
                self.paywall_frame,
                text="Activate a $10/month membership to unlock sealing and exports.",
                fg="#9aa4b2",
                bg="#0f1115",
                font=("Segoe UI", 11),
            ).pack(pady=(0, 18))

            self.paywall_status = tk.Label(
                self.paywall_frame,
                text="",
                fg="#f97316",
                bg="#0f1115",
            )
            self.paywall_status.pack(pady=(0, 12))

            drop_frame = tk.Frame(self.paywall_frame, bg="#0f1115")
            drop_frame.pack(pady=(0, 10))
            drop_label = tk.Label(
                drop_frame,
                text="Drag & drop your membership license here",
                fg="#94a3b8",
                bg="#0b1220",
                font=("Segoe UI", 10, "bold"),
                relief="ridge",
                bd=1,
                padx=10,
                pady=10,
            )
            drop_label.pack(fill="x", padx=40)
            self._enable_license_drop(drop_label)

            btn_frame = tk.Frame(self.paywall_frame, bg="#0f1115")
            btn_frame.pack(pady=6)

            tk.Button(
                btn_frame,
                text="Open payment link",
                command=self._open_payment_link,
                bg="#22c55e",
                fg="#0f1115",
                padx=12,
                pady=6,
                relief="flat",
            ).pack(side="left", padx=6)

            tk.Button(
                btn_frame,
                text="Check content verification",
                command=self._paywall_verify_content,
                bg="#111827",
                fg="#e2e8f0",
                padx=12,
                pady=6,
                relief="flat",
            ).pack(side="left", padx=6)

            tk.Button(
                btn_frame,
                text="Try preview app",
                command=self._enter_preview_mode,
                bg="#0b1220",
                fg="#e2e8f0",
                padx=12,
                pady=6,
                relief="flat",
            ).pack(side="left", padx=6)

            tk.Button(
                btn_frame,
                text="Load license",
                command=self._load_license_from_paywall,
                bg="#1f2937",
                fg="#e2e8f0",
                padx=12,
                pady=6,
                relief="flat",
            ).pack(side="left", padx=6)

            tk.Button(
                btn_frame,
                text="Check membership",
                command=self._check_membership_from_paywall,
                bg="#111827",
                fg="#e2e8f0",
                padx=12,
                pady=6,
                relief="flat",
            ).pack(side="left", padx=6)

        if message and self.paywall_status is not None:
            self.paywall_status.config(text=message)
        self.paywall_frame.pack(fill="both", expand=True)

    def _hide_paywall(self) -> None:
        if self.paywall_frame is not None:
            self.paywall_frame.pack_forget()
        if self.main_frame is not None:
            self.main_frame.pack(fill="both", expand=True)
        self._exit_preview_mode()

    def _open_payment_link(self) -> None:
        if PAYMENT_LINK:
            webbrowser.open(PAYMENT_LINK)

    def _load_license_from_paywall(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select membership license",
            filetypes=[("License", "*.originlicense"), ("All files", "*.*")],
        )
        if not file_path:
            return
        self._load_license_from_path(file_path)

    def _check_membership_from_paywall(self) -> None:
        ok, message = self._enforce_membership()
        if ok:
            self._hide_paywall()
            self._maybe_show_onboarding()
        else:
            if self.paywall_status is not None:
                self.paywall_status.config(text=message)

    def _load_license_from_path(self, file_path: str) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, LICENSE_PATH)
        self._check_membership_from_paywall()

    def _enable_license_drop(self, target: tk.Widget) -> None:
        if not DND_BACKEND_AVAILABLE:
            return
        try:
            target.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
            dnd_bind: Any = getattr(target, "dnd_bind", None)  # type: ignore[attr-defined]
            if callable(dnd_bind):
                dnd_bind(  # pylint: disable=not-callable
                    "<<Drop>>",
                    lambda event: self._handle_license_drop(event.data),
                )
        except Exception:
            return

    def _handle_license_drop(self, data: str) -> None:
        candidate = data.strip("{}")
        if not candidate:
            return
        path = Path(candidate)
        if not path.exists():
            return
        if path.suffix.lower() != ".originlicense":
            messagebox.showwarning("License", "Please drop a .originlicense file.")
            return
        self._load_license_from_path(str(path))

    def _paywall_verify_content(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select a video or image",
            filetypes=[
                ("Media files", "*.mp4 *.mov *.mkv *.jpg *.jpeg *.png *.webp *.gif *.tiff *.bmp"),
                ("Video files", "*.mp4 *.mov *.mkv"),
                ("Image files", "*.jpg *.jpeg *.png *.webp *.gif *.tiff *.bmp"),
                ("All files", "*.*"),
            ],
        )
        if not file_path:
            return
        self.media_path = Path(file_path)
        self._do_verify_content()

    def _enter_preview_mode(self) -> None:
        self.preview_mode = True
        if self.main_frame is not None:
            self.main_frame.pack(fill="both", expand=True)
        if self.paywall_frame is not None:
            self.paywall_frame.pack_forget()
        self._set_membership_controls(False)
        if self.membership_banner is not None:
            self.membership_banner.pack(pady=(0, 8))

    def _exit_preview_mode(self) -> None:
        self.preview_mode = False
        self._set_membership_controls(True)
        if self.membership_banner is not None:
            self.membership_banner.pack_forget()

    def _set_membership_controls(self, enabled: bool) -> None:
        for control in self.membership_controls:
            try:
                cast(Any, control).configure(state="normal" if enabled else "disabled")
            except tk.TclError:
                continue

    def _require_membership(self) -> bool:
        ok, reason = self._enforce_membership()
        if ok:
            return True
        messagebox.showwarning("Membership required", reason)
        self._show_paywall(reason)
        return False

    def select_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select a video or image",
            filetypes=[
                ("Media files", "*.mp4 *.mov *.mkv *.jpg *.jpeg *.png *.webp *.gif *.tiff *.bmp"),
                ("Video files", "*.mp4 *.mov *.mkv"),
                ("Image files", "*.jpg *.jpeg *.png *.webp *.gif *.tiff *.bmp"),
                ("All files", "*.*"),
            ],
        )
        if not file_path:
            return
        self.media_path = Path(file_path)
        self.file_label.config(text=str(self.media_path))
        self.status.config(text="File selected.")
        self._update_preview()
        self._log_event(f"Selected {self.media_path.name}")

    def _get_selected_platforms(self) -> list[str]:
        selections = self.platforms_list.curselection()
        return [self.platforms_list.get(idx) for idx in selections]

    def _select_all_platforms(self) -> None:
        self.platforms_list.select_set(0, tk.END)

    def _clear_platforms(self) -> None:
        self.platforms_list.select_clear(0, tk.END)

    def _pick_policy_file(self, kind: str) -> None:
        file_path = filedialog.askopenfilename(title=f"Select {kind.replace('_', ' ')}")
        if not file_path:
            return
        path = Path(file_path)
        if kind == "attestation":
            self.attestation_path = path
        elif kind == "attestation_sig":
            self.attestation_sig_path = path
        elif kind == "trust_store":
            self.trust_store_path = path
        elif kind == "registry":
            self.registry_path = path
        elif kind == "revocation":
            self.revocation_path = path
        self._log_event(f"Selected {kind} file")

    def handle_dropped_file(self, file_path: str) -> None:
        candidate = file_path.strip("{}")
        if not candidate:
            return
        path = Path(candidate)
        if not path.exists():
            return
        self.media_path = path
        self.file_label.config(text=str(self.media_path))
        self.status.config(text="File selected.")
        self._update_preview()
        self._log_event(f"Dropped {self.media_path.name}")

    def seal_content(self) -> None:
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return
        if not self._require_membership():
            self._log_event("Membership blocked: inactive")
            return
        creator_id = self.creator_entry.get().strip() or "creator-1"
        asset_id = self.asset_entry.get().strip() or "asset-1"
        platforms = self._get_selected_platforms()
        source_creator = self.source_creator_entry.get().strip() if self.source_creator_entry else ""
        source_asset = self.source_asset_entry.get().strip() if self.source_asset_entry else ""
        relationship = self.relationship_entry.get().strip() if self.relationship_entry else ""
        media_metadata = {
            key: value
            for key, value in {
                "source_creator_id": source_creator or None,
                "source_asset_id": source_asset or None,
                "relationship": relationship or None,
            }.items()
            if value
        }

        if not self.include_creator_id.get():
            creator_id = "redacted"
        if not self.include_asset_id.get():
            asset_id = "redacted"

        self._record_asset_entry(
            creator_id=creator_id,
            asset_id=asset_id,
            file_path=self.media_path,
            source_creator=source_creator,
            source_asset=source_asset,
            relationship=relationship,
        )

        private_path, public_path = ensure_keypair()
        private_key = load_private_key(private_path)

        manifest = build_manifest(
            file_path=self.media_path,
            creator_id=creator_id,
            asset_id=asset_id,
            intended_platforms=tuple(platforms) if self.include_platforms.get() else (),
            key_id=None if not self.include_key_id.get() else None,
            media_metadata=media_metadata or None,
        )

        output_dir = self.media_path.parent
        bundle_path = output_dir / f"{self.media_path.stem}.origin.zip"
        create_sealed_bundle(self.media_path, manifest, private_key, public_path, bundle_path)
        sidecar_path = output_dir / f"{self.media_path.name}.origin.json"
        if bundle_path.exists() or sidecar_path.exists():
            choice = messagebox.askyesnocancel(
                "Existing seal found",
                "A seal already exists for this file. Replace it?\n\n"
                "Yes: replace\nNo: keep both (versioned)\nCancel: skip",
            )
            if choice is None:
                self._log_event("Seal skipped")
                return
            if choice is False:
                bundle_path = output_dir / f"{self.media_path.stem}.origin.v2.zip"
                sidecar_path = output_dir / f"{self.media_path.name}.origin.v2.json"
        build_sidecar_from_bundle(bundle_path, self.media_path, sidecar_path)

        self._record_node_activity("sealed")

        self.status.config(text="Sealed and saved. Ready to verify.")
        self._log_event(f"Sealed {self.media_path.name}")
        self._update_preview()
        messagebox.showinfo(
            "Sealed",
            f"Your content is sealed.\n\nBundle: {bundle_path.name}\nSidecar: {sidecar_path.name}",
        )

    def verify_content(self) -> None:
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return

        self._do_verify_content()

    def _do_verify_content(self) -> None:
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return

        media_path = self.media_path
        bundle_path = media_path.parent / f"{media_path.stem}.origin.zip"
        sidecar_path = media_path.parent / f"{media_path.name}.origin.json"

        if bundle_path.exists():
            ok, _, reason = verify_sealed_bundle_detailed(bundle_path)
            self._show_verdict(ok, reason)
            self._record_node_activity("verified")
            return

        if sidecar_path.exists():
            payload_bytes = sidecar_path.read_bytes()
            errors = validate_origin_payload(payload_bytes)
            if errors:
                self._show_verdict(False, errors[0])
                self._record_node_activity("verified")
                return
            self._show_verdict(True, None)
            self._record_node_activity("verified")
            return

        payload = extract_origin_payload(media_path)
        if payload is None:
            self._show_verdict(False, "payload_missing_keys")
            self._record_node_activity("verified")
            return
        errors = validate_origin_payload(payload)
        self._show_verdict(len(errors) == 0, errors[0] if errors else None)
        self._record_node_activity("verified")

    def run_platform_check(self) -> None:
        if not self._require_membership():
            return
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return

        bundle_path = self.media_path.parent / f"{self.media_path.stem}.origin.zip"
        if not bundle_path.exists():
            messagebox.showinfo(
                "Platform check",
                "Seal a bundle first to run platform checks.",
            )
            return

        profile = (self.profile_var.get() or PolicyProfile.STANDARD).lower()
        if self.institutional_mode.get():
            profile = PolicyProfile.STRICT
        try:
            policy = build_policy_for_profile(profile)
        except ValueError:
            policy = build_policy_for_profile(PolicyProfile.STANDARD)

        if self.attestation_path:
            policy = replace(policy, attestation_path=self.attestation_path, require_attestation=True)
        if self.attestation_sig_path:
            policy = replace(policy, attestation_signature_path=self.attestation_sig_path)
        if self.trust_store_path:
            policy = replace(policy, trust_store_path=self.trust_store_path)
        if self.registry_path:
            policy = replace(policy, key_registry_path=self.registry_path, require_key_registry=True)
        if self.revocation_path:
            policy = replace(policy, revocation_list_path=self.revocation_path, require_revocation_check=True)

        platform = self.platform_var.get().strip()
        if platform:
            policy = replace(policy, platform=platform, require_platform_match=True)

        result = verify_sealed_bundle_with_policy(bundle_path, policy)
        if result.ok:
            message = f"{platform} ({profile}) check passed."
            self.platform_status.config(text=message, fg="#22c55e")
            self._log_event(f"Platform check passed: {platform} ({profile})")
            self._update_warning([])
            messagebox.showinfo("Platform check", message)
            self._record_node_activity("platform_checks")
            return

        reasons = ", ".join(human_reason(reason) for reason in result.reasons) or "Unknown issue"
        message = f"{platform} ({profile}) check failed: {reasons}"
        self.platform_status.config(text=message, fg="#f97316")
        self._log_event(f"Platform check failed: {platform} ({profile}) - {reasons}")
        self._update_warning(list(result.reasons))
        messagebox.showwarning("Platform check", message)
        self._record_node_activity("platform_checks")

    def _show_verdict(self, ok: bool, reason: str | None) -> None:
        if ok:
            self.status.config(text="Verified ✅")
            self.badge.config(text="Verified ✓", bg="#16a34a", fg="#0f1115")
            self._log_event("Verified successfully")
            if self.creator_card_status is not None:
                self.creator_card_status.config(text="Status: Verified", fg="#22c55e")
            self._update_warning([])
            messagebox.showinfo("Verified", "This file is authentic and ready to share.")
            return
        self.status.config(text="Needs attention")
        self.badge.config(text="Needs attention", bg="#f97316", fg="#0f1115")
        self._log_event(f"Needs attention: {reason}")
        if reason:
            self._update_warning([reason])
        if self.creator_card_status is not None:
            self.creator_card_status.config(text=f"Status: {human_reason(reason)}", fg="#f97316")
        messagebox.showwarning("Needs attention", human_reason(reason))

    def export_artifacts(self) -> None:
        if not self._require_membership():
            return
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return
        bundle_path = self.media_path.parent / f"{self.media_path.stem}.origin.zip"
        sidecar_path = self.media_path.parent / f"{self.media_path.name}.origin.json"
        if not bundle_path.exists() and not sidecar_path.exists():
            messagebox.showinfo("Nothing to export", "Seal the content first to generate artifacts.")
            return
        output_dir = filedialog.askdirectory(title="Choose export folder")
        if not output_dir:
            return
        output_path = Path(output_dir)
        if bundle_path.exists():
            shutil.copy2(bundle_path, output_path / bundle_path.name)
        if sidecar_path.exists():
            shutil.copy2(sidecar_path, output_path / sidecar_path.name)
        self._record_node_activity("exports")
        self._log_event("Exported artifacts")
        messagebox.showinfo("Exported", "Artifacts copied to the selected folder.")

    def export_publish_pack(self) -> None:
        if not self._require_membership():
            return
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return

        bundle_path = self.media_path.parent / f"{self.media_path.stem}.origin.zip"
        sidecar_path = self.media_path.parent / f"{self.media_path.name}.origin.json"
        if not bundle_path.exists() or not sidecar_path.exists():
            messagebox.showinfo("Publish pack", "Seal the content first to generate artifacts.")
            return

        output_dir = filedialog.askdirectory(title="Choose export folder")
        if not output_dir:
            return

        output_path = Path(output_dir) / f"{self.media_path.stem}.origin_publish.zip"
        with ZipFile(output_path, "w") as archive:
            archive.write(bundle_path, arcname=bundle_path.name)
            archive.write(sidecar_path, arcname=sidecar_path.name)
            archive.writestr(
                "README.txt",
                "Origin publish pack\n"
                "- bundle: sealed proof archive\n"
                "- sidecar: Origin metadata JSON\n",
            )

        self._record_node_activity("publish_exports")
        self._log_event("Exported publish pack")
        messagebox.showinfo("Publish pack", f"Publish pack saved to {output_path.name}.")

    def export_compliance_pack(self) -> None:
        if not self._require_membership():
            return
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return

        bundle_path = self.media_path.parent / f"{self.media_path.stem}.origin.zip"
        sidecar_path = self.media_path.parent / f"{self.media_path.name}.origin.json"
        if not bundle_path.exists() or not sidecar_path.exists():
            messagebox.showinfo("Compliance pack", "Seal the content first to generate artifacts.")
            return

        output_dir = filedialog.askdirectory(title="Choose export folder")
        if not output_dir:
            return

        output_path = Path(output_dir) / f"{self.media_path.stem}.origin_compliance.zip"
        with ZipFile(output_path, "w") as archive:
            archive.write(bundle_path, arcname=bundle_path.name)
            archive.write(sidecar_path, arcname=sidecar_path.name)
            if self.attestation_path:
                archive.write(self.attestation_path, arcname=f"attestation/{self.attestation_path.name}")
            if self.attestation_sig_path:
                archive.write(
                    self.attestation_sig_path,
                    arcname=f"attestation/{self.attestation_sig_path.name}",
                )
            if self.trust_store_path:
                archive.write(self.trust_store_path, arcname=f"trust_store/{self.trust_store_path.name}")
            if self.registry_path:
                archive.write(self.registry_path, arcname=f"registry/{self.registry_path.name}")
            if self.revocation_path:
                archive.write(self.revocation_path, arcname=f"revocation/{self.revocation_path.name}")
            archive.writestr(
                "README.txt",
                "Origin compliance pack\n"
                "- bundle: sealed proof archive\n"
                "- sidecar: Origin metadata JSON\n"
                "- attestation: optional issuer proof\n"
                "- trust_store / registry / revocation: optional policy evidence\n",
            )

        self._record_node_activity("compliance_exports")
        self._log_event("Exported compliance pack")
        messagebox.showinfo("Compliance pack", f"Compliance pack saved to {output_path.name}.")

    def open_folder(self) -> None:
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return
        folder = self.media_path.parent
        try:
            if sys.platform.startswith("win"):
                os.startfile(folder)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", str(folder)], check=False)
            else:
                subprocess.run(["xdg-open", str(folder)], check=False)
        except Exception:
            messagebox.showwarning("Open folder", "Unable to open the folder.")

    def manage_keys(self) -> None:
        private_path, public_path = ensure_keypair()
        dialog = tk.Toplevel(self)
        dialog.title("Key Management")
        dialog.configure(bg="#0f1115")
        dialog.geometry("520x240")

        tk.Label(
            dialog,
            text="Your signing keys",
            fg="#e5e7eb",
            bg="#0f1115",
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(14, 8))

        tk.Label(
            dialog,
            text=f"Public key: {public_path}",
            fg="#cbd5e1",
            bg="#0f1115",
            wraplength=480,
        ).pack(pady=4)

        tk.Label(
            dialog,
            text=f"Private key: {private_path}",
            fg="#cbd5e1",
            bg="#0f1115",
            wraplength=480,
        ).pack(pady=4)

        def regenerate() -> None:
            if not messagebox.askyesno(
                "Regenerate keys",
                "This will replace your current keys. Existing signatures will no longer verify. Continue?",
            ):
                return
            keypair = generate_keypair()
            save_keypair(keypair, KEYS_DIR)
            self._log_event("Regenerated keys")
            messagebox.showinfo("Keys regenerated", "New keys have been created.")
            dialog.destroy()

        tk.Button(
            dialog,
            text="Regenerate keys",
            command=regenerate,
            bg="#ef4444",
            fg="#0f1115",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=12)

    def _log_event(self, message: str) -> None:
        self.history.append(message)
        self.history_list.delete(0, tk.END)
        for item in self.history[-6:]:
            self.history_list.insert(tk.END, item)
        APP_DIR.mkdir(parents=True, exist_ok=True)
        AUDIT_LOG_PATH.write_text(
            "\n".join(self.history),
            encoding="utf-8",
        )

    def _record_asset_entry(
        self,
        creator_id: str,
        asset_id: str,
        file_path: Path,
        source_creator: str,
        source_asset: str,
        relationship: str,
    ) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        entry = {
            "created_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "creator_id": creator_id,
            "asset_id": asset_id,
            "file_name": file_path.name,
            "file_path": str(file_path),
            "source_creator_id": source_creator or None,
            "source_asset_id": source_asset or None,
            "relationship": relationship or None,
        }
        with ASSET_REGISTRY_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")

    def _read_state(self) -> dict[str, Any]:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        if STATE_PATH.exists():
            try:
                return json.loads(STATE_PATH.read_text())
            except Exception:
                return {}
        return {}

    def _write_state(self, state: dict[str, Any]) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(state, indent=2))

    def _load_bootstrap_config(self) -> dict[str, Any]:
        if not BOOTSTRAP_PATH.exists():
            return {}
        try:
            return json.loads(BOOTSTRAP_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _apply_bootstrap_defaults(self) -> None:
        state = self._read_state()
        bootstrap = self._load_bootstrap_config()
        changed = False

        if not state.get("license_ledger_cid") and bootstrap.get("ledger_cid"):
            state["license_ledger_cid"] = bootstrap["ledger_cid"]
            changed = True
        if not state.get("license_ledger_nodes") and bootstrap.get("node_endpoints"):
            state["license_ledger_nodes"] = list(bootstrap["node_endpoints"])
            changed = True
        if not state.get("license_ipfs_gateways") and bootstrap.get("ipfs_gateways"):
            state["license_ipfs_gateways"] = list(bootstrap["ipfs_gateways"])
            changed = True
        if not state.get("node_ledger_cid") and bootstrap.get("governance_ledger_cid"):
            state["node_ledger_cid"] = bootstrap["governance_ledger_cid"]
            changed = True
        if not state.get("node_ledger_nodes") and bootstrap.get("governance_node_endpoints"):
            state["node_ledger_nodes"] = list(bootstrap["governance_node_endpoints"])
            changed = True
        if not state.get("node_ipfs_gateways") and bootstrap.get("governance_ipfs_gateways"):
            state["node_ipfs_gateways"] = list(bootstrap["governance_ipfs_gateways"])
            changed = True

        if changed:
            self._write_state(state)

        if state.get("license_ledger_cid") and not state.get("license_last_check"):
            self._refresh_membership_ledger_from_nodes(
                state["license_ledger_cid"],
                list(state.get("license_ledger_nodes", [])),
                list(state.get("license_ipfs_gateways", [])),
            )

        if state.get("node_ledger_cid") and not state.get("node_ledger_last_check"):
            self._refresh_node_governance_from_nodes(
                state["node_ledger_cid"],
                list(state.get("node_ledger_nodes", [])),
                list(state.get("node_ipfs_gateways", [])),
            )

    def _refresh_membership_ledger(self, ledger_url: str) -> bool:
        try:
            response = urlrequest.urlopen(ledger_url, timeout=8)
            data = response.read()
            LICENSE_LEDGER_PATH.write_bytes(data)
            state = self._read_state()
            state["license_last_check"] = datetime.now(timezone.utc).isoformat()
            self._write_state(state)
            return True
        except Exception:
            return False

    def _parse_list_field(self, raw: str) -> list[str]:
        items: list[str] = []
        for chunk in raw.replace("\n", ",").split(","):
            item = chunk.strip()
            if item:
                items.append(item)
        return items

    def _build_ledger_fetch_urls(
        self,
        ledger_cid: str,
        endpoints: list[str],
        gateways: list[str],
    ) -> list[str]:
        urls: list[str] = []
        for endpoint in endpoints:
            if "{cid}" in endpoint:
                urls.append(endpoint.replace("{cid}", ledger_cid))
            else:
                base = endpoint.rstrip("/")
                urls.append(f"{base}/ledger/{ledger_cid}")
                urls.append(f"{base}/ipfs/{ledger_cid}")
        for gateway in gateways:
            if "{cid}" in gateway:
                urls.append(gateway.replace("{cid}", ledger_cid))
            else:
                urls.append(f"{gateway.rstrip('/')}/ipfs/{ledger_cid}")
        return urls

    def _matches_ledger_cid(self, ledger_cid: str, data: bytes) -> bool:
        if not ledger_cid:
            return True
        value = ledger_cid.strip().lower()
        if value.startswith("sha256:"):
            value = value.split(":", 1)[1]
        if len(value) != 64:
            return True
        return hashlib.sha256(data).hexdigest() == value

    def _refresh_membership_ledger_from_nodes(
        self,
        ledger_cid: str,
        endpoints: list[str],
        gateways: list[str],
    ) -> bool:
        if not ledger_cid:
            return False
        urls = self._build_ledger_fetch_urls(ledger_cid, endpoints, gateways)
        for url in urls:
            try:
                response = urlrequest.urlopen(url, timeout=8)
                data = response.read()
                if not self._matches_ledger_cid(ledger_cid, data):
                    continue
                LICENSE_LEDGER_PATH.write_bytes(data)
                state = self._read_state()
                state["license_last_check"] = datetime.now(timezone.utc).isoformat()
                self._write_state(state)
                return True
            except Exception:
                continue
        return False

    def _refresh_node_governance_from_nodes(
        self,
        ledger_cid: str,
        endpoints: list[str],
        gateways: list[str],
    ) -> bool:
        if not ledger_cid:
            return False
        urls = self._build_ledger_fetch_urls(ledger_cid, endpoints, gateways)
        for url in urls:
            try:
                response = urlrequest.urlopen(url, timeout=8)
                data = response.read()
                data_hash = hashlib.sha256(data).hexdigest()
                if not self._matches_ledger_cid(ledger_cid, data):
                    self._show_tamper_alert(
                        title="Governance ledger CID mismatch",
                        details={
                            "source_url": url,
                            "expected_cid": ledger_cid,
                            "computed_hash": f"sha256:{data_hash}",
                            "note": "Content hash does not match expected CID.",
                        },
                    )
                    continue
                payload = json.loads(data)
                ledger = node_ledger_from_bytes(json.dumps(payload["ledger"]).encode("utf-8"))
                signature = base64.b64decode(payload["signature"])
                public_key_pem = payload["public_key"]
                public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
                if not verify_node_ledger(ledger, signature, public_key):
                    self._show_tamper_alert(
                        title="Governance ledger signature invalid",
                        details={
                            "source_url": url,
                            "expected_cid": ledger_cid,
                            "computed_hash": f"sha256:{data_hash}",
                            "public_key": public_key_pem,
                            "note": "Signature verification failed.",
                        },
                    )
                    continue
                NODE_GOVERNANCE_PATH.write_bytes(data)
                state = self._read_state()
                state["node_ledger_last_check"] = datetime.now(timezone.utc).isoformat()
                state["authority_nodes"] = sorted(compute_authority_set(ledger))
                self._write_state(state)
                return True
            except Exception:
                continue
        return False

    def _refresh_node_governance(self) -> None:
        state = self._read_state()
        ledger_cid = state.get("node_ledger_cid")
        ledger_nodes = state.get("node_ledger_nodes", [])
        ipfs_gateways = state.get("node_ipfs_gateways", [])
        last_check = state.get("node_ledger_last_check")
        if ledger_cid:
            should_refresh = True
            if last_check:
                try:
                    last_dt = datetime.fromisoformat(last_check)
                    should_refresh = (datetime.now(timezone.utc) - last_dt).total_seconds() >= 24 * 3600
                except ValueError:
                    should_refresh = True
            if should_refresh:
                self._refresh_node_governance_from_nodes(
                    ledger_cid,
                    list(ledger_nodes or []),
                    list(ipfs_gateways or []),
                )

        if not NODE_GOVERNANCE_PATH.exists():
            return
        try:
            ledger, signature, public_key_pem = read_node_ledger_file(str(NODE_GOVERNANCE_PATH))
            public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
            if not verify_node_ledger(ledger, signature, public_key):
                self._show_tamper_alert(
                    title="Governance ledger signature invalid",
                    details={
                        "source": str(NODE_GOVERNANCE_PATH),
                        "note": "Local governance ledger failed signature verification.",
                    },
                )
                return
            authorities = sorted(compute_authority_set(ledger))
            state = self._read_state()
            state["authority_nodes"] = authorities
            state["node_ledger_last_check"] = datetime.now(timezone.utc).isoformat()
            self._write_state(state)
        except Exception:
            return

    def _show_tamper_alert(self, title: str, details: dict[str, Any]) -> None:
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.configure(bg="#0f1115")
        dialog.geometry("640x360")

        tk.Label(
            dialog,
            text=title,
            fg="#f87171",
            bg="#0f1115",
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(14, 8))

        details = dict(details)
        details["detected_at"] = datetime.now(timezone.utc).isoformat()

        text = tk.Text(
            dialog,
            bg="#0b1220",
            fg="#e5e7eb",
            wrap="word",
            relief="flat",
        )
        text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        text.insert("1.0", json.dumps(details, indent=2, sort_keys=True))
        text.configure(state="disabled")

        tk.Button(
            dialog,
            text="Close",
            command=dialog.destroy,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=(0, 12))

    def _apply_license_ledger(self, license_obj: Any) -> tuple[Any, bool]:
        if not LICENSE_LEDGER_PATH.exists():
            return license_obj, False
        try:
            ledger, signature, public_key_pem = read_license_ledger_file(LICENSE_LEDGER_PATH)
            public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
            if not verify_license_ledger(ledger, signature, public_key):
                return license_obj, False
        except Exception:
            return license_obj, False

        revoked = False
        updated = license_obj
        for entry in ledger.entries:
            if entry.license_id != license_obj.license_id:
                continue
            revoked = True
            if entry.updated_expires_at:
                updated = replace(updated, expires_at=entry.updated_expires_at)
            if entry.updated_plan:
                updated = replace(updated, plan=entry.updated_plan)
            if entry.updated_features is not None:
                updated = replace(updated, features=tuple(entry.updated_features))
            if entry.updated_device_fingerprint:
                updated = replace(updated, device_fingerprint=entry.updated_device_fingerprint)
        return updated, revoked

    def _enforce_membership(self) -> tuple[bool, str]:
        if owner_override_enabled():
            return True, "Owner access active."
        if not LICENSE_PATH.exists():
            return False, "Membership license not loaded."

        try:
            license_obj, signature, public_key_pem = read_license_file(LICENSE_PATH)
            public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
            if not verify_license(license_obj, signature, public_key):
                return False, "License signature invalid."
        except Exception:
            return False, "Membership license unreadable."

        state = self._read_state()
        ledger_url = state.get("license_ledger_url")
        ledger_cid = state.get("license_ledger_cid")
        ledger_nodes = state.get("license_ledger_nodes", [])
        ipfs_gateways = state.get("license_ipfs_gateways", [])
        last_check = state.get("license_last_check")
        if ledger_url:
            should_refresh = True
            if last_check:
                try:
                    last_dt = datetime.fromisoformat(last_check)
                    should_refresh = (datetime.now(timezone.utc) - last_dt).total_seconds() >= 24 * 3600
                except ValueError:
                    should_refresh = True
            if should_refresh:
                self._refresh_membership_ledger(ledger_url)
        elif ledger_cid:
            should_refresh = True
            if last_check:
                try:
                    last_dt = datetime.fromisoformat(last_check)
                    should_refresh = (datetime.now(timezone.utc) - last_dt).total_seconds() >= 24 * 3600
                except ValueError:
                    should_refresh = True
            if should_refresh:
                self._refresh_membership_ledger_from_nodes(
                    ledger_cid,
                    list(ledger_nodes or []),
                    list(ipfs_gateways or []),
                )

        license_obj, revoked = self._apply_license_ledger(license_obj)
        if revoked:
            return False, "Membership revoked or updated by ledger."

        errors = validate_license(license_obj, device_fingerprint=device_fingerprint())
        if errors:
            return False, "Membership inactive: " + ", ".join(errors)

        if license_obj.offline_grace_days is not None:
            if not last_check:
                return False, "Membership requires ledger check."
            try:
                last_dt = datetime.fromisoformat(last_check)
                grace_seconds = int(license_obj.offline_grace_days) * 24 * 3600
                if (datetime.now(timezone.utc) - last_dt).total_seconds() > grace_seconds:
                    return False, "Membership expired due to offline grace window."
            except ValueError:
                return False, "Membership ledger timestamp invalid."

        return True, "Membership active."

    def _open_membership(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Membership")
        dialog.configure(bg="#0f1115")
        dialog.geometry("620x420")

        tk.Label(
            dialog,
            text="Membership license",
            fg="#e5e7eb",
            bg="#0f1115",
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(14, 6))

        status = tk.Label(dialog, text="", fg="#cbd5e1", bg="#0f1115")
        status.pack(pady=(0, 10))

        def refresh_status() -> None:
            ok, message = self._enforce_membership()
            status.config(text=message, fg="#22c55e" if ok else "#f97316")
            if ok:
                self._exit_preview_mode()
            details_text.configure(state="normal")
            details_text.delete("1.0", tk.END)
            details_text.insert("1.0", self._describe_license())
            details_text.configure(state="disabled")

        def load_license() -> None:
            file_path = filedialog.askopenfilename(
                title="Select membership license",
                filetypes=[("License", "*.originlicense"), ("All files", "*.*")],
            )
            if not file_path:
                return
            APP_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, LICENSE_PATH)
            refresh_status()

        state = self._read_state()

        details_text = tk.Text(
            dialog,
            height=6,
            bg="#0b1220",
            fg="#cbd5e1",
            wrap="word",
            relief="flat",
        )
        details_text.pack(fill="x", padx=14, pady=(0, 8))
        details_text.insert("1.0", "Loading license details...")
        details_text.configure(state="disabled")

        cid_frame = tk.Frame(dialog, bg="#0f1115")
        cid_frame.pack(fill="x", padx=14, pady=(0, 6))
        tk.Label(cid_frame, text="Ledger CID", fg="#cbd5e1", bg="#0f1115").pack(side="left")
        ledger_cid_entry = tk.Entry(cid_frame, width=50)
        ledger_cid_entry.pack(side="left", padx=8)
        if state.get("license_ledger_cid"):
            ledger_cid_entry.insert(0, state["license_ledger_cid"])

        nodes_frame = tk.Frame(dialog, bg="#0f1115")
        nodes_frame.pack(fill="x", padx=14, pady=(0, 6))
        tk.Label(nodes_frame, text="Node endpoints", fg="#cbd5e1", bg="#0f1115").pack(side="left")
        nodes_entry = tk.Entry(nodes_frame, width=50)
        nodes_entry.pack(side="left", padx=8)
        nodes_default = ",".join(state.get("license_ledger_nodes", []) or DEFAULT_NODE_ENDPOINTS)
        if nodes_default:
            nodes_entry.insert(0, nodes_default)

        gateways_frame = tk.Frame(dialog, bg="#0f1115")
        gateways_frame.pack(fill="x", padx=14, pady=(0, 6))
        tk.Label(gateways_frame, text="IPFS gateways", fg="#cbd5e1", bg="#0f1115").pack(side="left")
        gateways_entry = tk.Entry(gateways_frame, width=50)
        gateways_entry.pack(side="left", padx=8)
        gateways_default = ",".join(state.get("license_ipfs_gateways", []) or DEFAULT_IPFS_GATEWAYS)
        if gateways_default:
            gateways_entry.insert(0, gateways_default)

        gov_cid_frame = tk.Frame(dialog, bg="#0f1115")
        gov_cid_frame.pack(fill="x", padx=14, pady=(8, 6))
        tk.Label(gov_cid_frame, text="Governance CID", fg="#cbd5e1", bg="#0f1115").pack(side="left")
        gov_cid_entry = tk.Entry(gov_cid_frame, width=50)
        gov_cid_entry.pack(side="left", padx=8)
        if state.get("node_ledger_cid"):
            gov_cid_entry.insert(0, state["node_ledger_cid"])

        gov_nodes_frame = tk.Frame(dialog, bg="#0f1115")
        gov_nodes_frame.pack(fill="x", padx=14, pady=(0, 6))
        tk.Label(gov_nodes_frame, text="Governance nodes", fg="#cbd5e1", bg="#0f1115").pack(side="left")
        gov_nodes_entry = tk.Entry(gov_nodes_frame, width=50)
        gov_nodes_entry.pack(side="left", padx=8)
        gov_nodes_default = ",".join(state.get("node_ledger_nodes", []) or DEFAULT_NODE_ENDPOINTS)
        if gov_nodes_default:
            gov_nodes_entry.insert(0, gov_nodes_default)

        gov_gateways_frame = tk.Frame(dialog, bg="#0f1115")
        gov_gateways_frame.pack(fill="x", padx=14, pady=(0, 6))
        tk.Label(gov_gateways_frame, text="Governance gateways", fg="#cbd5e1", bg="#0f1115").pack(side="left")
        gov_gateways_entry = tk.Entry(gov_gateways_frame, width=50)
        gov_gateways_entry.pack(side="left", padx=8)
        gov_gateways_default = ",".join(state.get("node_ipfs_gateways", []) or DEFAULT_IPFS_GATEWAYS)
        if gov_gateways_default:
            gov_gateways_entry.insert(0, gov_gateways_default)

        def save_ledger_settings() -> None:
            state = self._read_state()
            state["license_ledger_cid"] = ledger_cid_entry.get().strip()
            state["license_ledger_nodes"] = self._parse_list_field(nodes_entry.get())
            state["license_ipfs_gateways"] = self._parse_list_field(gateways_entry.get())
            if state.get("license_ledger_url"):
                state.pop("license_ledger_url", None)
            self._write_state(state)
            refresh_status()

        def refresh_ledger() -> None:
            cid = ledger_cid_entry.get().strip()
            nodes = self._parse_list_field(nodes_entry.get())
            gateways = self._parse_list_field(gateways_entry.get())
            if not cid:
                messagebox.showwarning("Ledger", "Enter a ledger CID first.")
                return
            self._set_status_bar("Refreshing ledger...", level="info", auto_clear=False)
            ok = self._refresh_membership_ledger_from_nodes(cid, nodes, gateways)
            if ok:
                messagebox.showinfo("Ledger", "Ledger refreshed.")
            else:
                messagebox.showwarning("Ledger", "Unable to refresh ledger.")
            self._set_status_bar("Ledger refresh complete.", level="success")
            refresh_status()

        def save_governance_settings() -> None:
            state = self._read_state()
            state["node_ledger_cid"] = gov_cid_entry.get().strip()
            state["node_ledger_nodes"] = self._parse_list_field(gov_nodes_entry.get())
            state["node_ipfs_gateways"] = self._parse_list_field(gov_gateways_entry.get())
            self._write_state(state)
            self._refresh_node_governance()
            refresh_status()

        def refresh_governance() -> None:
            cid = gov_cid_entry.get().strip()
            nodes = self._parse_list_field(gov_nodes_entry.get())
            gateways = self._parse_list_field(gov_gateways_entry.get())
            if not cid:
                messagebox.showwarning("Governance", "Enter a governance CID first.")
                return
            self._set_status_bar("Refreshing governance...", level="info", auto_clear=False)
            ok = self._refresh_node_governance_from_nodes(cid, nodes, gateways)
            if ok:
                messagebox.showinfo("Governance", "Governance ledger refreshed.")
            else:
                messagebox.showwarning("Governance", "Unable to refresh governance ledger.")
            self._set_status_bar("Governance refresh complete.", level="success")
            refresh_status()

        btn_frame = tk.Frame(dialog, bg="#0f1115")
        btn_frame.pack(pady=8)
        tk.Button(
            btn_frame,
            text="Load license",
            command=load_license,
            bg="#111827",
            fg="#e2e8f0",
            padx=10,
            pady=4,
            relief="flat",
        ).pack(side="left", padx=6)
        tk.Button(
            btn_frame,
            text="Save ledger settings",
            command=save_ledger_settings,
            bg="#111827",
            fg="#e2e8f0",
            padx=10,
            pady=4,
            relief="flat",
        ).pack(side="left", padx=6)
        tk.Button(
            btn_frame,
            text="Refresh ledger",
            command=refresh_ledger,
            bg="#111827",
            fg="#e2e8f0",
            padx=10,
            pady=4,
            relief="flat",
        ).pack(side="left", padx=6)
        tk.Button(
            btn_frame,
            text="Ledger status",
            command=self._open_ledger_status,
            bg="#111827",
            fg="#e2e8f0",
            padx=10,
            pady=4,
            relief="flat",
        ).pack(side="left", padx=6)

        gov_btn_frame = tk.Frame(dialog, bg="#0f1115")
        gov_btn_frame.pack(pady=6)
        tk.Button(
            gov_btn_frame,
            text="Save governance settings",
            command=save_governance_settings,
            bg="#111827",
            fg="#e2e8f0",
            padx=10,
            pady=4,
            relief="flat",
        ).pack(side="left", padx=6)
        tk.Button(
            gov_btn_frame,
            text="Refresh governance",
            command=refresh_governance,
            bg="#111827",
            fg="#e2e8f0",
            padx=10,
            pady=4,
            relief="flat",
        ).pack(side="left", padx=6)

        refresh_status()

        tk.Button(
            dialog,
            text="Close",
            command=dialog.destroy,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=(8, 12))

    def _open_asset_library(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Asset library")
        dialog.configure(bg="#0f1115")
        dialog.geometry("640x360")

        tk.Label(
            dialog,
            text="Protected assets",
            fg="#e5e7eb",
            bg="#0f1115",
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(14, 8))

        content = tk.Frame(dialog, bg="#0f1115")
        content.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        list_frame = tk.Frame(content, bg="#0f1115")
        list_frame.pack(side="left", fill="both", expand=True)

        listbox = tk.Listbox(list_frame, bg="#111827", fg="#e5e7eb", height=12)
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
        scrollbar.pack(side="right", fill="y")
        listbox.configure(yscrollcommand=scrollbar.set)

        detail = tk.Text(
            content,
            bg="#0b1220",
            fg="#cbd5e1",
            width=32,
            wrap="word",
            relief="flat",
        )
        detail.pack(side="left", fill="both", expand=False, padx=(12, 0))
        detail.insert("1.0", "Select an asset to view details.")
        detail.configure(state="disabled")

        entries: list[dict[str, Any]] = []
        if ASSET_REGISTRY_PATH.exists():
            try:
                for line in ASSET_REGISTRY_PATH.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            except Exception:
                pass

        if not entries:
            listbox.insert(tk.END, "No assets logged yet")
        else:
            for entry in entries:
                asset_id = entry.get("asset_id", "unknown")
                file_name = entry.get("file_name", "unknown")
                created_at = entry.get("created_at", "")
                listbox.insert(tk.END, f"{asset_id} · {file_name} · {created_at}")

        def on_select(_event: tk.Event) -> None:
            if not entries:
                return
            selection = listbox.curselection()
            if not selection:
                return
            idx = selection[0]
            if idx >= len(entries):
                return
            entry = entries[idx]
            detail_lines = [
                f"Asset ID: {entry.get('asset_id', 'unknown')}",
                f"Creator ID: {entry.get('creator_id', 'unknown')}",
                f"File: {entry.get('file_name', 'unknown')}",
                f"Path: {entry.get('file_path', '')}",
                f"Created: {entry.get('created_at', '')}",
            ]
            source_creator = entry.get("source_creator_id")
            source_asset = entry.get("source_asset_id")
            relationship = entry.get("relationship")
            if source_creator or source_asset:
                detail_lines.append(
                    f"Provenance: {source_creator or 'unknown'} / {source_asset or 'unknown'}"
                )
                if relationship:
                    detail_lines.append(f"Relationship: {relationship}")

            detail.configure(state="normal")
            detail.delete("1.0", tk.END)
            detail.insert("1.0", "\n".join(detail_lines))
            detail.configure(state="disabled")

        listbox.bind("<<ListboxSelect>>", on_select)

        tk.Button(
            dialog,
            text="Close",
            command=dialog.destroy,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=(0, 12))

    def _update_preview(self) -> None:
        if not self.media_path:
            return

        is_image = self.media_path.suffix.lower() in IMAGE_SUFFIXES

        bundle_path = self.media_path.parent / f"{self.media_path.stem}.origin.zip"
        sidecar_path = self.media_path.parent / f"{self.media_path.name}.origin.json"

        lines = [f"File: {self.media_path.name}"]

        manifest_data = None
        if bundle_path.exists():
            try:
                with ZipFile(bundle_path, "r") as bundle:
                    manifest_data = json.loads(bundle.read("manifest.json").decode("utf-8"))
                lines.append(f"Bundle: {bundle_path.name}")
            except Exception:
                pass

        if manifest_data is None and sidecar_path.exists():
            try:
                sidecar = json.loads(sidecar_path.read_text())
                payload = sidecar.get("payload", {})
                manifest_b64 = payload.get("manifest.json")
                if isinstance(manifest_b64, str):
                    manifest_data = json.loads(
                        __import__("base64").b64decode(manifest_b64.encode("ascii")).decode("utf-8")
                    )
                lines.append(f"Sidecar: {sidecar_path.name}")
            except Exception:
                pass

        if manifest_data:
            lines.append(f"Creator ID: {manifest_data.get('creator_id', 'unknown')}")
            lines.append(f"Asset ID: {manifest_data.get('asset_id', 'unknown')}")
            lines.append(f"Created: {manifest_data.get('created_at', 'unknown')}")
            platforms = manifest_data.get("intended_platforms", [])
            if platforms:
                lines.append(f"Intended platforms: {', '.join(platforms)}")
            if manifest_data.get("key_id"):
                lines.append(f"Key ID: {manifest_data['key_id']}")
            meta = manifest_data.get("media_metadata") or {}
            if isinstance(meta, dict):
                source_creator = meta.get("source_creator_id")
                source_asset = meta.get("source_asset_id")
                relationship = meta.get("relationship")
                if source_creator or source_asset:
                    lines.append(
                        "Provenance: "
                        f"{source_creator or 'unknown'}"
                        f" / {source_asset or 'unknown'}"
                        f" ({relationship or 'derived'})"
                    )
            if self.creator_card_meta is not None:
                creator = manifest_data.get("creator_id", "unknown")
                asset = manifest_data.get("asset_id", "unknown")
                self.creator_card_meta.config(text=f"Original Creator: {creator} • Asset: {asset}")
            if self.creator_card_platform is not None:
                platform = self.platform_var.get().strip() or "—"
                self.creator_card_platform.config(text=f"Platform view: {platform}")
        else:
            lines.append("No metadata found yet. Seal the file to embed proof.")
            if self.creator_card_meta is not None:
                self.creator_card_meta.config(text="Original Creator: —")
            if self.creator_card_platform is not None:
                self.creator_card_platform.config(text="Platform view: —")

        lines.append("")
        lines.append("Supported: MP4, MOV, MKV, JPG, PNG, WEBP, GIF, TIFF, BMP, Sidecar JSON, Sealed bundles")
        lines.append("Coming soon: WebM, ProRes")
        if is_image:
            lines.append("")
            lines.append("Note: Image verification requires the original file.")
            lines.append("Resizing or recompressing changes the hash and will fail verification.")

        if self.institutional_mode.get():
            lines = lines[:4]
            lines.append("Use Origin verification for compliance and attribution.")

        self.preview_text.configure(state="normal")
        self.preview_text.delete("1.0", tk.END)
        self.preview_text.insert("1.0", "\n".join(lines))
        self.preview_text.configure(state="disabled")

        if self.creator_card_status is not None:
            self.creator_card_status.config(text="Status: Pending verification", fg="#94a3b8")
        self._update_warning([])
        if self.creator_card_label is not None:
            label = "Origin Verified for Institutions" if self.institutional_mode.get() else "Origin Protected"
            self.creator_card_label.config(text=label)

    def _update_warning(self, reasons: list[str]) -> None:
        if self.warning_label is None:
            return
        warning_map = {
            "key_id_mismatch": "Creator identity mismatch",
            "key_untrusted": "Creator key not trusted",
            "revoked": "Creator key revoked",
            "attestation_invalid": "Attestation invalid",
            "attestation_expired": "Attestation expired",
            "attestation_missing": "Attestation missing",
            "trust_store_missing": "Trust store missing",
            "trust_store_empty": "Trust store empty",
            "key_registry_missing": "Registry missing",
        }
        messages = [warning_map.get(reason, "") for reason in reasons if reason in warning_map]
        messages = [message for message in messages if message]
        if not messages:
            self.warning_label.config(text="")
            return
        joined = " • ".join(dict.fromkeys(messages))
        self.warning_label.config(text=f"Protection alert: {joined}")

    def _enable_drag_and_drop(self) -> None:
        if DND_BACKEND_AVAILABLE:
            try:
                self.drop_label.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
                dnd_bind: Any = getattr(self.drop_label, "dnd_bind", None)  # type: ignore[attr-defined]
                if callable(dnd_bind):
                    dnd_bind(  # pylint: disable=not-callable
                        "<<Drop>>",
                        lambda event: self.handle_dropped_file(event.data),
                    )
                self._dnd_available = True
                return
            except Exception:
                self._dnd_available = False

        try:
            self.tk.call("package", "require", "tkdnd")
            self.drop_label.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
            dnd_bind: Any = getattr(self.drop_label, "dnd_bind", None)  # type: ignore[attr-defined]
            if callable(dnd_bind):
                dnd_bind(  # pylint: disable=not-callable
                    "<<Drop>>",
                    lambda event: self.handle_dropped_file(event.data),
                )
            self._dnd_available = True
        except Exception:
            self._dnd_available = False
            self.drop_label.config(text="Drag & drop not available (use Choose File)")

    def _attach_tooltip(self, widget: tk.Widget, text: str) -> None:
        widget.bind("<Enter>", lambda _event: self._schedule_tooltip(widget, text))
        widget.bind("<Leave>", lambda _event: self._hide_tooltip())

    def _schedule_tooltip(self, widget: tk.Widget, text: str) -> None:
        if self._tooltip_after_id is not None:
            self.after_cancel(self._tooltip_after_id)
        self._tooltip_after_id = self.after(300, lambda: self._show_tooltip(widget, text))

    def _show_tooltip(self, widget: tk.Widget, text: str) -> None:
        if self.tooltip_label is None:
            return
        self.tooltip_label.config(text=text)
        x = widget.winfo_rootx() - self.winfo_rootx()
        y = widget.winfo_rooty() - self.winfo_rooty() + widget.winfo_height() + 6
        self.tooltip_label.place(x=x, y=y)

    def _hide_tooltip(self) -> None:
        if self._tooltip_after_id is not None:
            self.after_cancel(self._tooltip_after_id)
            self._tooltip_after_id = None
        if self.tooltip_label is not None:
            self.tooltip_label.place_forget()

    def _maybe_show_onboarding(self) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        state = {}
        if STATE_PATH.exists():
            try:
                state = json.loads(STATE_PATH.read_text())
            except Exception:
                state = {}
        if state.get("onboarded"):
            return

        if self.onboarding_frame is None:
            self.onboarding_frame = tk.Frame(self, bg="#0f1115")

        if self.main_frame is not None:
            self.main_frame.pack_forget()

        self.onboarding_frame.pack(fill="both", expand=True)

        header = tk.Label(
            self.onboarding_frame,
            text="Welcome to Origin Protocol",
            fg="#e5e7eb",
            bg="#0f1115",
            font=("Segoe UI", 16, "bold"),
        )
        header.pack(pady=(24, 12))

        content = tk.Label(
            self.onboarding_frame,
            text=(
                "Origin is a portable, tamper‑evident credit layer.\n\n"
                "When you seal a video, anyone can verify:\n"
                "• Original creator\n"
                "• Authenticity\n"
                "• Provenance\n\n"
                "Platforms can display: \"Origin Protected — Original Creator: You\"\n"
                "even after re‑uploads, remixes, or transcoding."
            ),
            fg="#e5e7eb",
            bg="#0f1115",
            justify="left",
            font=("Segoe UI", 11),
        )
        content.pack(pady=(0, 16), padx=24)

        def use_sample() -> None:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            if FIXTURE_SAMPLE_PATH.exists() and not SAMPLE_MEDIA_PATH.exists():
                shutil.copy2(FIXTURE_SAMPLE_PATH, SAMPLE_MEDIA_PATH)
            if not SAMPLE_MEDIA_PATH.exists():
                messagebox.showwarning(
                    "Sample unavailable",
                    "Sample media could not be loaded. Please choose a file instead.",
                )
                return
            self.media_path = SAMPLE_MEDIA_PATH
            self.file_label.config(text=str(self.media_path))
            self._update_preview()
            self._log_event("Loaded sample media")
            finish()

        tk.Button(
            self.onboarding_frame,
            text="Try sealing the example",
            command=use_sample,
            bg="#22c55e",
            fg="#0f1115",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=(0, 12))

        def finish() -> None:
            STATE_PATH.write_text(json.dumps({"onboarded": True}, indent=2))
            if self.onboarding_frame is not None:
                self.onboarding_frame.pack_forget()
            if self.main_frame is not None:
                self.main_frame.pack(fill="both", expand=True)

        tk.Button(
            self.onboarding_frame,
            text="You’re ready",
            command=finish,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=(0, 8))

    def _open_learn_more(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Learn more")
        dialog.configure(bg="#0f1115")
        dialog.geometry("520x320")

        tk.Label(
            dialog,
            text="Why Origin matters",
            fg="#e5e7eb",
            bg="#0f1115",
            font=("Segoe UI", 13, "bold"),
        ).pack(pady=(16, 8))

        content_frame = tk.Frame(dialog, bg="#0f1115")
        content_frame.pack(fill="both", expand=True, padx=12)
        info_text = tk.Text(
            content_frame,
            bg="#0f1115",
            fg="#cbd5e1",
            font=("Segoe UI", 10),
            wrap="word",
            relief="flat",
            height=10,
        )
        info_text.pack(side="left", fill="both", expand=True, pady=(0, 12))
        info_scroll = tk.Scrollbar(content_frame, orient="vertical", command=info_text.yview)
        info_scroll.pack(side="right", fill="y", pady=(0, 12))
        info_text.configure(yscrollcommand=info_scroll.set)
        info_text.insert(
            "1.0",
            "Origin keeps your authorship attached to your work.\n\n"
            "What it does:\n"
            "• Seals a tamper-evident proof into your media\n"
            "• Preserves creator attribution across re-uploads\n"
            "• Lets platforms verify authenticity and provenance\n\n"
            "Common questions:\n"
            "• Sidecar: A small proof file saved next to your media.\n"
            "• Attestation: Optional statement from a trusted issuer.\n"
            "• Registry: List of approved signing keys.\n\n"
            "How to use it:\n"
            "1) Select a video and click Seal\n"
            "2) Verify to confirm the embedded proof\n"
            "3) Export a publish or compliance pack when needed"
        )
        info_text.configure(state="disabled")

        tk.Button(
            dialog,
            text="Close",
            command=dialog.destroy,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=(0, 16))

    def apply_accessibility(self) -> None:
        base_font = 11 if self.large_text.get() else 10
        fg = "#ffffff" if self.high_contrast.get() else "#cbd5e1"
        bg = "#0f1115" if self.high_contrast.get() else "#0f1115"
        self.status.config(font=("Segoe UI", base_font), fg=fg, bg=bg)
        self.file_label.config(font=("Segoe UI", base_font), fg=fg, bg=bg)
        self.preview_text.config(font=("Segoe UI", base_font))
        self.history_list.config(font=("Segoe UI", base_font))
        if self.status_bar is not None:
            self.status_bar.config(font=("Segoe UI", max(9, base_font - 1)), fg=fg, bg=bg)

    def copy_artifact(self, artifact: str) -> None:
        if not self._require_membership():
            return
        if not self.media_path:
            messagebox.showinfo("Select a file", "Please choose a video first.")
            return
        bundle_path = self.media_path.parent / f"{self.media_path.stem}.origin.zip"
        sidecar_path = self.media_path.parent / f"{self.media_path.name}.origin.json"
        target = bundle_path if artifact == "bundle" else sidecar_path
        if not target.exists():
            messagebox.showinfo("Not found", "Seal the content first to generate artifacts.")
            return
        self.clipboard_clear()
        self.clipboard_append(str(target))
        self._log_event(f"Copied {artifact} path")
        messagebox.showinfo("Copied", f"{artifact.capitalize()} path copied to clipboard.")

    def batch_process(self) -> None:
        if not self._require_membership():
            return
        folder = filedialog.askdirectory(title="Select a folder")
        if not folder:
            return
        root = Path(folder)
        files = [
            p
            for p in root.iterdir()
            if p.suffix.lower()
            in {".mp4", ".mov", ".mkv", ".jpg", ".jpeg", ".png", ".webp", ".gif", ".tiff", ".bmp"}
        ]
        if not files:
            messagebox.showinfo("No media", "No supported videos or images found in this folder.")
            return

        dialog = tk.Toplevel(self)
        dialog.title("Batch processing")
        dialog.configure(bg="#0f1115")
        dialog.geometry("560x360")

        listbox = tk.Listbox(dialog, bg="#111827", fg="#e5e7eb")
        listbox.pack(fill="both", expand=True, padx=12, pady=12)
        for item in files:
            listbox.insert(tk.END, item.name)

        progress = tk.Label(dialog, text="Ready", fg="#cbd5e1", bg="#0f1115")
        progress.pack(pady=6)

        def seal_all() -> None:
            self._set_status_bar("Batch sealing in progress...", level="info", auto_clear=False)
            for idx, file_path in enumerate(files, start=1):
                self.media_path = file_path
                progress.config(text=f"Sealing {idx}/{len(files)}: {file_path.name}")
                dialog.update_idletasks()
                self.seal_content()
            progress.config(text="Batch sealing complete.")
            self._log_event("Batch sealing complete")
            self._set_status_bar("Batch sealing complete.", level="success")
            self._record_node_activity("batch_seals")

        def verify_all() -> None:
            self._set_status_bar("Batch verification in progress...", level="info", auto_clear=False)
            for idx, file_path in enumerate(files, start=1):
                self.media_path = file_path
                progress.config(text=f"Verifying {idx}/{len(files)}: {file_path.name}")
                dialog.update_idletasks()
                self.verify_content()
            progress.config(text="Batch verification complete.")
            self._log_event("Batch verification complete")
            self._set_status_bar("Batch verification complete.", level="success")
            self._record_node_activity("batch_verifies")

    def _load_node_metrics(self) -> dict[str, Any]:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        if NODE_METRICS_PATH.exists():
            try:
                return json.loads(NODE_METRICS_PATH.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_node_metrics(self, metrics: dict[str, Any]) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        NODE_METRICS_PATH.write_text(json.dumps(metrics, indent=2))

    def _record_node_activity(self, metric: str) -> None:
        metrics = self._load_node_metrics()
        counts = metrics.get("counts")
        if not isinstance(counts, dict):
            counts = {}

        counts[metric] = int(counts.get(metric, 0)) + 1
        metrics["counts"] = counts

        now = datetime.now(timezone.utc)
        metrics.setdefault("created_at", now.isoformat())
        metrics["last_active_at"] = now.isoformat()

        active_days = metrics.get("active_days")
        if not isinstance(active_days, list):
            active_days = []
        today = now.date().isoformat()
        if today not in active_days:
            active_days.append(today)
        metrics["active_days"] = active_days

        self._save_node_metrics(metrics)

    def _set_status_bar(self, text: str, level: str = "info", auto_clear: bool = True) -> None:
        if self.status_bar is None:
            return
        colors = {
            "info": "#94a3b8",
            "success": "#22c55e",
            "warning": "#f97316",
            "error": "#ef4444",
        }
        self.status_bar.config(text=text, fg=colors.get(level, "#94a3b8"))
        if self._status_after_id is not None:
            self.after_cancel(self._status_after_id)
            self._status_after_id = None
        if auto_clear:
            self._status_after_id = self.after(4000, self._clear_status_bar)

    def _clear_status_bar(self) -> None:
        if self.status_bar is None:
            return
        self.status_bar.config(text="", fg="#94a3b8")
        self._status_after_id = None

    def _describe_license(self) -> str:
        if not LICENSE_PATH.exists():
            return "No membership license loaded."
        try:
            license_obj, signature, public_key_pem = read_license_file(LICENSE_PATH)
            public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
            signature_ok = verify_license(license_obj, signature, public_key)
            errors = validate_license(license_obj, device_fingerprint=device_fingerprint())
        except Exception:
            return "Membership license unreadable."

        def get_field(name: str, fallback: str = "—") -> str:
            value = getattr(license_obj, name, None)
            if value is None:
                return fallback
            if isinstance(value, (list, tuple)):
                return ", ".join(str(item) for item in value) if value else fallback
            return str(value)

        fingerprint = get_field("device_fingerprint", "")
        fingerprint_display = f"{fingerprint[:10]}…" if fingerprint else "—"
        details = [
            f"Plan: {get_field('plan')}",
            f"License ID: {get_field('license_id')}",
            f"Issued: {get_field('issued_at')}",
            f"Expires: {get_field('expires_at')}",
            f"Features: {get_field('features')}",
            f"Offline grace (days): {get_field('offline_grace_days')}",
            f"Device binding: {fingerprint_display}",
            f"Signature: {'valid' if signature_ok else 'invalid'}",
        ]
        if errors:
            details.append("Status: " + ", ".join(errors))
        else:
            details.append("Status: active")
        return "\n".join(details)

    def _open_ledger_status(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Ledger status")
        dialog.configure(bg="#0f1115")
        dialog.geometry("520x320")

        tk.Label(
            dialog,
            text="Membership ledger status",
            fg="#e5e7eb",
            bg="#0f1115",
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(14, 8))

        state = self._read_state()
        ledger_cid = state.get("license_ledger_cid", "")
        last_check = state.get("license_last_check", "—")
        authority_nodes = state.get("authority_nodes", [])
        node_ledger_cid = state.get("node_ledger_cid", "")
        node_last_check = state.get("node_ledger_last_check", "—")

        status_lines = [
            f"Ledger CID: {ledger_cid or '—'}",
            f"Last check: {last_check or '—'}",
            f"Governance CID: {node_ledger_cid or '—'}",
            f"Governance check: {node_last_check or '—'}",
            f"Authority nodes: {len(authority_nodes) if isinstance(authority_nodes, list) else 0}",
        ]

        if LICENSE_LEDGER_PATH.exists():
            data = LICENSE_LEDGER_PATH.read_bytes()
            ledger_hash = hashlib.sha256(data).hexdigest()
            status_lines.append(f"Ledger hash: {ledger_hash}")
            matches = self._matches_ledger_cid(str(ledger_cid), data)
            status_lines.append(f"CID match: {'yes' if matches else 'no'}")
            try:
                ledger, signature, public_key_pem = read_license_ledger_file(LICENSE_LEDGER_PATH)
                public_key = load_public_key_bytes(public_key_pem.encode("utf-8"))
                signature_ok = verify_license_ledger(ledger, signature, public_key)
                status_lines.append(f"Signature: {'valid' if signature_ok else 'invalid'}")
            except Exception:
                status_lines.append("Signature: unable to verify")
        else:
            status_lines.append("Ledger file: not found")

        status_text = tk.Text(
            dialog,
            height=10,
            bg="#0b1220",
            fg="#cbd5e1",
            wrap="word",
            relief="flat",
        )
        status_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        status_text.insert("1.0", "\n".join(status_lines))
        status_text.configure(state="disabled")

        tk.Button(
            dialog,
            text="Close",
            command=dialog.destroy,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=(0, 12))

    def export_diagnostics(self) -> None:
        if not self._require_membership():
            return
        output_dir = filedialog.askdirectory(title="Choose diagnostics folder")
        if not output_dir:
            return
        include_license = messagebox.askyesno(
            "Include license",
            "Include membership license file in diagnostics?",
        )

        output_path = Path(output_dir) / f"origin_diagnostics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        summary = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "state": self._read_state(),
            "ledger_hash": None,
            "node_ledger_hash": None,
        }
        if LICENSE_LEDGER_PATH.exists():
            summary["ledger_hash"] = hashlib.sha256(LICENSE_LEDGER_PATH.read_bytes()).hexdigest()
        if NODE_GOVERNANCE_PATH.exists():
            summary["node_ledger_hash"] = hashlib.sha256(NODE_GOVERNANCE_PATH.read_bytes()).hexdigest()

        self._set_status_bar("Exporting diagnostics...", level="info", auto_clear=False)
        with ZipFile(output_path, "w") as archive:
            if STATE_PATH.exists():
                archive.write(STATE_PATH, arcname="state.json")
            if AUDIT_LOG_PATH.exists():
                archive.write(AUDIT_LOG_PATH, arcname="audit_log.jsonl")
            if ASSET_REGISTRY_PATH.exists():
                archive.write(ASSET_REGISTRY_PATH, arcname="asset_registry.jsonl")
            if LICENSE_LEDGER_PATH.exists():
                archive.write(LICENSE_LEDGER_PATH, arcname="license_ledger.json")
            if NODE_GOVERNANCE_PATH.exists():
                archive.write(NODE_GOVERNANCE_PATH, arcname="node_ledger.json")
            if include_license and LICENSE_PATH.exists():
                archive.write(LICENSE_PATH, arcname="membership.originlicense")
            archive.writestr("diagnostics.json", json.dumps(summary, indent=2))
            archive.writestr(
                "README.txt",
                "Origin diagnostics bundle\n"
                "- state.json: app state\n"
                "- audit_log.jsonl: recent activity\n"
                "- asset_registry.jsonl: sealed assets\n"
                "- license_ledger.json: membership ledger (if present)\n"
                "- diagnostics.json: summary metadata\n",
            )

        self._set_status_bar("Diagnostics exported.", level="success")
        messagebox.showinfo("Diagnostics", f"Diagnostics saved to {output_path.name}.")

    def _open_settings(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Settings")
        dialog.configure(bg="#0f1115")
        dialog.geometry("420x260")

        tk.Label(
            dialog,
            text="Appearance & behavior",
            fg="#e5e7eb",
            bg="#0f1115",
            font=("Segoe UI", 12, "bold"),
        ).pack(pady=(14, 8))

        content = tk.Frame(dialog, bg="#0f1115")
        content.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        tk.Checkbutton(
            content,
            text="Large text",
            variable=self.large_text,
            command=self.apply_accessibility,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).pack(anchor="w", pady=4)
        tk.Checkbutton(
            content,
            text="High contrast",
            variable=self.high_contrast,
            command=self.apply_accessibility,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).pack(anchor="w", pady=4)
        tk.Checkbutton(
            content,
            text="Institutional mode",
            variable=self.institutional_mode,
            command=self._update_preview,
            fg="#cbd5e1",
            bg="#0f1115",
            activebackground="#0f1115",
            selectcolor="#0f1115",
        ).pack(anchor="w", pady=4)

        tk.Button(
            dialog,
            text="Close",
            command=dialog.destroy,
            bg="#1f2937",
            fg="#e2e8f0",
            padx=12,
            pady=6,
            relief="flat",
        ).pack(pady=(0, 12))


if __name__ == "__main__":
    app = CreatorApp()
    app.mainloop()
