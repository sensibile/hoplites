CREATE TABLE debian_license_alias (label TEXT PRIMARY KEY, spdx_expression TEXT NOT NULL);
INSERT INTO debian_license_alias VALUES
 ('apache-2','Apache-2.0'), ('apache-2.0','Apache-2.0'),
 ('bsd-2-clause','BSD-2-Clause'), ('bsd-3-clause','BSD-3-Clause'),
 ('bsd-4-clause','BSD-4-Clause'), ('bsd-4-clause-uc','BSD-4-Clause-UC'),
 ('mit','MIT'), ('expat','MIT'), ('isc','ISC'), ('zlib','Zlib'),
 ('curl','curl'), ('openldap-2.8','OLDAP-2.8'), ('oldap-2.8','OLDAP-2.8'),
 ('cc0-1.0','CC0-1.0'), ('bsl-1.0','BSL-1.0'), ('fsfap','FSFAP'),
 ('fsfullr','FSFULLR'), ('fsful','FSFUL'),
 ('latex2e','Latex2e'), ('x11','X11'),
 ('ftl','FTL'), ('artistic-2','Artistic-2.0'), ('mpl-1.1','MPL-1.1'),
 ('cc-by-3.0','CC-BY-3.0'), ('ms-pl','MS-PL');
