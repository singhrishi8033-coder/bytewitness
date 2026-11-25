# ByteWitness

An offline static file triage CLI for the first five minutes of an investigation. Given one or more files, it records their SHA-256 fingerprints, recognizes common file signatures, locates URL-like strings and measures byte entropy. Each observation can be checked against the original bytes. Written in Python with standard-library dependencies only.

## Try a case

With Python 3.9 or later, open a terminal in this directory and run

```sh
python bytewitness.py --watchlist examples/watchlist.txt examples/invoice.txt
python -m unittest -v
```

The training file contains a harmless URL and its hash is on the demo watchlist. Find the URL in the JSON output, then verify the offset by counting the bytes before it. Make a copy, append one character, and rescan. The URL remains at the same offset while the watchlist match disappears. This demonstrates a limitation of exact-hash detection.

## Investigating a file

```sh
python bytewitness.py file1.bin file2.pdf > case.json
```

| Evidence | Interpretation |
| --- | --- |
| SHA-256 watchlist match | File contents match a hash selected by the analyst. List membership carries only the meaning assigned by its curator. |
| Unexpected PE extension | A DOS header points to a PE signature with room for a COFF header, while the filename uses an unusual extension. This is a lead for manual inspection. |
| Embedded URL | An ASCII HTTP(S)-like string is present at a zero-based byte offset. The scanner never contacts the destination. |
| High-entropy window | An aligned 4 KiB window measures at least 7.5 bits per byte. Compressed media and encrypted data can both trigger this observation. |

The scanner opens regular files up to 16 MiB and processes them sequentially. The JSON includes exact match counts and the first 32 examples per evidence category per file. URL text is limited to 512 bytes after the scheme. Partial entropy windows are skipped. Signatures are shallow format clues. The tool does not decode archives, extract UTF-16 strings, verify PE loadability, or classify a file as malicious. No risk score or accuracy benchmark is claimed.

A watchlist accepts one SHA-256 digest per line, blank lines, and comments starting with `#`. Exit code 0 means all inputs were processed, 1 means at least one input failed (successful reports are retained), and 2 indicates a usage or watchlist error. Reports can contain sensitive strings from the input files.

## Engineering walkthrough

`read_regular` bounds input size, `identify` checks signatures, and `collect` returns a JSON-compatible evidence record. For a file of n bytes, the hashing, string scan and window histograms each take linear time. Tests exercise malformed headers, batch errors, evidence caps, and exact entropy-window boundaries.
