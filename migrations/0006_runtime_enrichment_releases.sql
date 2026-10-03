-- Reviewed Elixir/Erlang release evidence, independent of a particular run archive.
CREATE TABLE runtime_enrichment_release (
 name TEXT NOT NULL, version TEXT NOT NULL, purl TEXT NOT NULL,
 license_id TEXT NOT NULL, license_url TEXT NOT NULL, license_sha256 TEXT NOT NULL,
 source_commit TEXT NOT NULL, version_marker TEXT NOT NULL,
 PRIMARY KEY(name,version)
);
INSERT INTO runtime_enrichment_release VALUES
 ('elixir','1.18.4','pkg:generic/elixir@1.18.4','Apache-2.0','https://raw.githubusercontent.com/elixir-lang/elixir/7b20c281d521aa7aa2ad2baa1e9ae6c579d79d0c/LICENSE','a6cba85bc92e0cff7a450b1d873c0eaa2e9fc96bf472df0247a26bec77bf3ff9','7b20c281d521aa7aa2ad2baa1e9ae6c579d79d0c','usr/local/lib/elixir/lib/elixir/ebin/elixir.app'),
 ('erlang','28.5.0.7','pkg:generic/erlang@28.5.0.7','Apache-2.0','https://raw.githubusercontent.com/erlang/otp/09fb046150ab94104e03ee816b95c8b7e6b04683/LICENSE.txt','809fa1ed21450f59827d1e9aec720bbc4b687434fa22283c6cb5dd82a47ab9c0','09fb046150ab94104e03ee816b95c8b7e6b04683','usr/local/lib/erlang/releases/28/OTP_VERSION');
