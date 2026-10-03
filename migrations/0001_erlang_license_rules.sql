-- Reviewed source/build selectors, not a claim that every image includes these files.
CREATE TABLE source_release (
  project TEXT NOT NULL, version TEXT NOT NULL, source_sha256 TEXT NOT NULL,
  PRIMARY KEY (project, version)
);
CREATE TABLE embedded_license_rule (
  project TEXT NOT NULL, version TEXT NOT NULL, name TEXT NOT NULL,
  source_path TEXT NOT NULL, expression TEXT NOT NULL, binary_indicator TEXT NOT NULL,
  PRIMARY KEY (project, version, name),
  FOREIGN KEY (project, version) REFERENCES source_release(project, version)
);
INSERT INTO source_release VALUES ('erlang','28.5.0.7','ddf17db6d3e9b7a7cfac0d72238ddc8ea040fedc5e3dfad82fc90675319d6c93');
INSERT INTO embedded_license_rule VALUES
 ('erlang','28.5.0.7','PCRE2','erts/emulator/pcre/LICENCE','BSD-3-Clause WITH PCRE2-exception','pcre2'),
 ('erlang','28.5.0.7','AsmJit','erts/emulator/asmjit/LICENSE.md','Zlib','asmjit'),
 ('erlang','28.5.0.7','Zstandard','erts/emulator/zstd/common/zstd_common.c','BSD-3-Clause OR GPL-2.0-only','ZSTD_'),
 ('erlang','28.5.0.7','zlib','erts/emulator/zlib/zlib.h','Zlib','zlib'),
 ('erlang','28.5.0.7','Ryu','erts/emulator/ryu/d2s.c','Apache-2.0 OR BSL-1.0','ryu'),
 ('erlang','28.5.0.7','Ryu formatting adapter','erts/emulator/ryu/to_chars.h','Apache-2.0 WITH LLVM-exception AND BSL-1.0','ryu');
