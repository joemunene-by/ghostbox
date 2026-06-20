# Changelog

All notable changes to ghostbox are documented in this file. The format is based
on Keep a Changelog, and this project adheres to semantic versioning.

## [0.1.0] - 2026-06-21

Initial release.

### Added
- Static analysis engine with a modular Analyzer base class and registry. Every
  analyzer runs in isolation; a failure in one is recorded as a warning and never
  aborts the run. No analyzer ever executes a sample.
- Hashing analyzer: md5, sha1, sha256, and file size.
- Filetype analyzer: magic-byte detection (PE, ELF, Mach-O, PDF, OLE/OOXML Office,
  scripts, archives) with no native dependency on libmagic.
- PE analyzer: DOS/NT header, section table, and import parsing via pefile when
  available, with a built-in fallback parser. Flags suspicious imports.
- ELF analyzer: header, section table, and dynamic symbols via pyelftools when
  available, with a built-in 32/64-bit fallback parser.
- Entropy and packer heuristics: whole-file and per-section Shannon entropy, with
  known-packer section-name detection (UPX, ASPack, Themida, VMProtect, and more).
- Strings and IOC extraction: ASCII and UTF-16LE strings, then URLs, IPv4, domains,
  emails, Windows paths, registry keys, and mutexes.
- Capability tagging: maps imports and string patterns to behavior tags
  (networking, process injection, persistence, anti-debug, crypto/ransomware,
  discovery, process execution, keylogging).
- Optional YARA scanning gated on yara-python; degrades cleanly when absent.
- Explainable threat score: weighted aggregation of signals into a 0-100 score with
  clean / suspicious / malicious bands and a full list of contributing signals.
- Typer plus rich CLI: `analyze`, `scan`, `rules`, `version`, with `--format`,
  `--yara-dir`, `--min-score`, `--output`, `--max-strings`, and `--verbose`.
- Console and JSON report output.
- Test suite using programmatically crafted benign samples; passes under bare
  pytest. YARA tests use importorskip.
