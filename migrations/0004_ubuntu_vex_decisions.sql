-- Reviewed, exact-version experiment decisions. No blanket CPE suppression.
-- Fixed releases .2 and .4 precede reviewed installed .6 in the same Ubuntu packaging branch.
CREATE TABLE distro_vex_decision (
 cve TEXT NOT NULL, distro TEXT NOT NULL, source_package TEXT NOT NULL,
 binary_package TEXT NOT NULL, reviewed_version TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('resolved','not_affected')),
 fixed_version TEXT NOT NULL, source_url TEXT NOT NULL, source_sha256 TEXT NOT NULL,
 reviewed_at TEXT NOT NULL,
 PRIMARY KEY(cve,distro,source_package,binary_package,reviewed_version)
);
INSERT INTO distro_vex_decision VALUES
 ('CVE-2025-30258','ubuntu-24.04','gnupg2','gnupg','2.4.4-2ubuntu17.6','resolved','2.4.4-2ubuntu17.2','https://ubuntu.com/security/CVE-2025-30258','9461dff5c71d0ac7f204448699f31a616656a768ad49b618f22bcba0b41107da','2026-10-03'),
 ('CVE-2025-68973','ubuntu-24.04','gnupg2','gnupg','2.4.4-2ubuntu17.6','resolved','2.4.4-2ubuntu17.4','https://ubuntu.com/security/CVE-2025-68973','12951c0d9d564431fa7188ab5bc168748f7b3aecd90319d6b12f0d7af9d6fca8','2026-10-03'),
 ('CVE-2025-68972','ubuntu-24.04','gnupg2','gnupg','2.4.4-2ubuntu17.6','not_affected','','https://ubuntu.com/security/CVE-2025-68972','ae9ec29a56e9c33e362c3a477ab8b668799d11d3f26046e1d535095bcec4a17e','2026-10-03');
