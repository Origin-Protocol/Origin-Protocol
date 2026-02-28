# Origin Creator Tool (Desktop EXE)

Simple desktop app for:
- sealing a local content file (SHA-256 + bundle metadata)
- verifying against Origin API
- publishing sealed metadata to Origin Social backend

## Run locally

```powershell
cd Origin-Protocol/experimental/creator-tool
python -m pip install -r requirements.txt
python app.py
```

## Build Windows EXE

```powershell
cd Origin-Protocol/experimental/creator-tool
pwsh -ExecutionPolicy Bypass -File .\build_exe.ps1
```

Output:
- `dist/OriginCreatorTool/OriginCreatorTool.exe`

## Required inputs

- `API Base URL` (example: `https://originapp.fly.dev/api`)
- `Creator ID`
- `Key ID`
- `Origin ID` (optional)
- `Ingest Key` (optional; if server enforces `X-Origin-Ingest-Key`)
- `Video URL` (public URL for publish step)

## Notes

- Verify call uses `POST /origin/verify`.
- Publish call defaults to `POST /videos/sync/sealed`; if that fails, tool retries `POST /videos/sealed`.
- Sealed payload can be exported to JSON and reused.
