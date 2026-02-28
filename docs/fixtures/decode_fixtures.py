import base64
from pathlib import Path

FIXTURE_DIR = Path(__file__).parent

FIXTURES = {
    "mp4_embedded_base64.txt": "origin_fixture.mp4",
    "mkv_embedded_base64.txt": "origin_fixture.mkv",
}


def decode_fixture(input_name: str, output_name: str) -> Path:
    data = (FIXTURE_DIR / input_name).read_text().strip()
    output_path = FIXTURE_DIR / output_name
    output_path.write_bytes(base64.b64decode(data))
    return output_path


def main() -> None:
    for source, target in FIXTURES.items():
        output_path = decode_fixture(source, target)
        print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
