import json
import pathlib
import struct
import subprocess
import sys

qpack_bin, work, out, nghttp3_commit, lsqpack_commit = sys.argv[1:6]
work, out = pathlib.Path(work), pathlib.Path(out)
qifs = work / "ls-qpack" / "test" / "qifs"

# *.qif files obtained from ls-qpack repo containing header lists
QIFS = [
    ("fb-req.qif",      256),
    ("fb-req.qif",     4096),
    ("fb-resp.qif",     256),
    ("fb-resp.qif",    4096),
    ("long-codes.qif",  256),
    ("long-codes.qif", 4096),
    ("netbsd.qif",      256),
    ("netbsd.qif",      512),
    ("netbsd.qif",     4096),
]

def clean_qif(raw):
    """Drop `#` comment lines (long-codes.qif opens with a comment block),
    preserving everything else byte-for-byte."""
    return b"\n".join(
        ln for ln in raw.split(b"\n") if not ln.startswith(b"#"))

def parse_qif(raw):
    """Header blocks, replicating nghttp3's qpack_encode.cc QIF reader:
    blank-line separated blocks, `name\tvalue` lines, leading spaces of
    values stripped. Names/values are opaque bytes; non-UTF-8 content is
    mapped 1:1 onto code points (latin-1), so JSON escapes are lossless."""
    blocks = []

    for block in clean_qif(raw).split(b"\n\n"):
        lines = [ln for ln in block.split(b"\n") if ln != b""]
        if not lines:
            continue

        headers = []
        for ln in lines:
            name, sep, value = ln.partition(b"\t")
            assert sep, f"no TAB in {ln!r}"
            headers.append([name.decode("latin-1"),
                            value.lstrip(b" ").decode("latin-1")])
        blocks.append(headers)
    return blocks

def parse_records(raw):
    records = []
    pos = 0
    while pos + 12 <= len(raw):
        sid, ln = struct.unpack(">QI", raw[pos:pos + 12])
        rec = {"stream_id": sid, "wire": raw[pos + 12:pos + 12 + ln].hex()}
        if sid != 0:
            rec["headers"] = None
        records.append(rec)
        pos += 12 + ln

    assert pos == len(raw), "trailing bytes in encoded output"
    return records

for name, size in QIFS:
    raw = (qifs / name).read_bytes()
    blocks = parse_qif(raw)
    cleaned = work / f"{name}.clean"
    cleaned.write_bytes(clean_qif(raw))
    encoded = work / f"{name}.{size}"

    # Use external QPACK encoder using nghttp3
    subprocess.run(
        [qpack_bin, "encode", str(cleaned), str(encoded),
         "-s", str(size), "-m", "100"],
        check=True, capture_output=True)

    records = parse_records(encoded.read_bytes())
    sections = [r for r in records if r["stream_id"] != 0]
    assert len(sections) == len(blocks), (
        f"{name}@{size}: {len(sections)} sections vs {len(blocks)} blocks")

    for rec, block in zip(sections, blocks):
        rec["headers"] = block

    story = {
        "description": f"Real-world {name[:-4]} header lists encoded by the "
                       "nghttp3 qpack example tool",
        "source": f"nghttp3 {nghttp3_commit} examples/qpack_encode.cc; "
                  f"ls-qpack {lsqpack_commit} test/qifs/{name}",
        "table_capacity": size,
        "max_blocked_streams": 100,
        "delay_encoder_stream": True,
        "cases": [
            {"seqno": i, **rec} for i, rec in enumerate(records)
        ],
    }

    target = out / "nghttp3" / f"{name[:-4]}-{size}.json"
    target.write_text(json.dumps(story, indent=2, ensure_ascii=True) + "\n")
    print(f"{target.name}: {len(blocks)} sections, "
          f"{sum(len(r['wire']) // 2 for r in records)} wire bytes")
