#!/usr/bin/env python3
"""BL-037 (Fable 5 whole-repository review R-13): repository実データ全件
schema regression test。標準ライブラリの unittest のみを使用する。

役割: mainに保存されている全daily JSON(data/YYYY-MM-DD.json)に対する、
read-onlyのschema regression test。test_pipeline_e2e.Bl037PipelineE2ETestが
fetch.main()を実際に呼び出すpipeline integration E2Eであるのに対し、本fileは
既に保存済みのrepository実データを対象にした独立したread-only検証である。
次の3層を区別して検証する(「全fileが同じstrict schemaを満たす」わけではない)。

1. JSON parse／filename-digest_date一致(schema versionによらず全fileへ適用)。
2. historical schema(v1)のarchive-read互換性検証: 全fileへ
   `daily_json.validate_daily_digest_for_archive_read()`を適用する。
3. current schema(v2)のstrict save-time検証: schema v2のfileだけへ、
   明示的に`daily_json.validate_daily_digest()`も適用する
   (validate_daily_digest_for_archive_read()は内部でv2をこの関数へ委譲する
   ため実質的には同じ検証だが、本fileでも明示的に検証することで、将来
   委譲関係が変わってもschema v2への厳格な検証が暗黙のまま失われない
   ようにする)。schema v1へこのstrict validatorを遡及適用することはしない。

対象fileはtest実行時に`data/`直下に存在する`daily_json.DAILY_FILENAME_RE`
一致fileすべてを動的に取得する(件数を固定値へロックしない)。data/index.json・
cache file・test fixture・temporary fileは対象外。

test中にdata fileやindexを書き換えない(read-only)。historical schema v1を
schema v2へ書き換えない。validatorを弱めたり、validation失敗fileをskipしたり
しない — 失敗した場合はfilenameと元exceptionを含めてtestを失敗させる。

validatorの選択について(pre-flight調査で確定): `daily_json.validate_daily_digest()`
は自身のdocstringで明記されている通り「保存直前専用」であり、schema v1
(レガシー)の実在fileへ現行のBrief件数上限・enum等を遡及適用してしまう。
repository実データを対象に`validate_daily_digest()`を直接使うと、
`data/2026-07-14.json`(4件の`brief.check_items`。生成当時は正当な実データ)
のような、production自身が既知として扱っているfileまで誤って失敗させる。
production側(fetch.py の generate_archive_outputs()・
load_validated_published_digest_dates())は、この理由から一貫して
schema-versionを判定し、schema v2には`validate_daily_digest()`と同じstrict
validationを適用しつつschema v1は現行閾値を遡及適用しない
`daily_json.validate_daily_digest_for_archive_read()`を使っている
(fetch.py:1987-1993のdocstring参照)。本testもこれに合わせ、
`validate_daily_digest_for_archive_read()`を全fileへ一様に適用する
(内部でschema v2はvalidate_daily_digest()へ委譲するため、v2に対する
strict validationは変わらない)。runtime(daily_json.py)は変更していない。
"""

import json
import unittest
from pathlib import Path

import daily_json

REPOSITORY_ROOT = Path(__file__).resolve().parent
DATA_DIR = REPOSITORY_ROOT / "data"


def _discover_daily_digest_files():
    if not DATA_DIR.is_dir():
        return []
    return sorted(
        p for p in DATA_DIR.iterdir()
        if p.is_file() and daily_json.DAILY_FILENAME_RE.fullmatch(p.name)
    )


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


class Bl037RepositoryDataValidationTest(unittest.TestCase):
    """repositoryの`data/`直下にある全daily JSON(`data/index.json`・cache・
    fixture・temporary fileを除く)が、production自身がArchive読込・
    再生成に使うのと同じ`daily_json.validate_daily_digest_for_archive_read()`
    契約(schema v2はvalidate_daily_digest()と同じstrict validation、
    schema v1は現行閾値を遡及適用しない後方互換validation)を満たすことを
    検証する、read-onlyのschema regression test。
    """

    @classmethod
    def setUpClass(cls):
        # path一覧の取得だけを行い、内容のparseはしない(round 2レビュー
        # 指摘への対応)。ここでJSONをparseすると、将来UTF-8不正・JSON破損
        # fileが1件でも追加された場合にsetUpClass()自体が例外送出し、
        # filenameを明示する個別subTestへ到達する前にclass全体のtestが
        # 一括で失敗してしまう(どのfileが原因か分からない失敗を招く)。
        cls.daily_digest_paths = _discover_daily_digest_files()

    def test_at_least_one_daily_digest_file_exists(self):
        self.assertGreaterEqual(
            len(self.daily_digest_paths), 1,
            "data/直下にYYYY-MM-DD.json形式のfileが1件も見つからない",
        )

    def test_every_daily_digest_file_is_valid_utf8_json_object(self):
        for path in self.daily_digest_paths:
            with self.subTest(file=path.name):
                try:
                    raw = path.read_text(encoding="utf-8")
                except UnicodeDecodeError as e:
                    self.fail(f"{path.name}: UTF-8として読み込めません: {e}")
                try:
                    document = json.loads(raw)
                except json.JSONDecodeError as e:
                    self.fail(f"{path.name}: JSONとしてparseできません: {e}")
                self.assertIsInstance(
                    document, dict, f"{path.name}: top-levelがobjectではありません(型: {type(document).__name__})"
                )

    def test_every_daily_digest_file_passes_validate_daily_digest_for_archive_read(self):
        for path in self.daily_digest_paths:
            with self.subTest(file=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                try:
                    daily_json.validate_daily_digest_for_archive_read(document)
                except daily_json.DailyJsonError as e:
                    self.fail(
                        f"{path.name}: validate_daily_digest_for_archive_read()が失敗しました: {e}"
                    )

    def test_current_schema_files_pass_strict_save_time_validation(self):
        # schema v2(current)のfileだけへ、明示的にstrictな
        # daily_json.validate_daily_digest()も適用する。schema v2の抽出自体
        # (どのfileがv2かの判定にはparseが必要)もこのtest method内で、
        # file単位のsubTestの中で行う(setUpClass()では一切parseしない。
        # round 2レビュー指摘への対応)。これにより、1件のfileがUTF-8不正・
        # JSON破損であっても、そのfile自身のsubTestだけがfilenameを含めて
        # 失敗し、他の全fileの検証やこのclassの他のtest methodには
        # 影響しない。件数はtest実行時に動的に抽出し固定しない。
        # schema v1(historical)へこのstrict validatorを遡及適用しない
        # (archive-read互換性検証は上のtest_every_daily_digest_file_passes_
        # validate_daily_digest_for_archive_readが別途担う)。
        found_schema_v2_file = False
        for path in self.daily_digest_paths:
            with self.subTest(file=path.name):
                document = _load(path)
                if document.get("schema_version") != daily_json.SCHEMA_VERSION:
                    continue
                found_schema_v2_file = True
                try:
                    daily_json.validate_daily_digest(document)
                except daily_json.DailyJsonError as e:
                    self.fail(f"{path.name}: validate_daily_digest()(strict)が失敗しました: {e}")
        if not found_schema_v2_file:
            self.skipTest("repositoryにschema v2のdaily digest fileが現在1件も無い")

    def test_every_daily_digest_filename_date_matches_its_digest_date_field(self):
        for path in self.daily_digest_paths:
            with self.subTest(file=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                filename_date = path.stem  # "YYYY-MM-DD.json" -> "YYYY-MM-DD"
                self.assertEqual(
                    document.get("digest_date"), filename_date,
                    f"{path.name}: filenameの日付({filename_date!r})と"
                    f"digest_date({document.get('digest_date')!r})が一致しません",
                )

    def test_every_daily_digest_schema_version_is_within_validator_supported_range(self):
        for path in self.daily_digest_paths:
            with self.subTest(file=path.name):
                document = json.loads(path.read_text(encoding="utf-8"))
                schema_version = document.get("schema_version")
                self.assertIn(
                    schema_version,
                    (daily_json.LEGACY_SCHEMA_VERSION, daily_json.SCHEMA_VERSION),
                    f"{path.name}: schema_version({schema_version!r})が"
                    f"validatorの対応範囲(  {daily_json.LEGACY_SCHEMA_VERSION}, "
                    f"{daily_json.SCHEMA_VERSION})外です",
                )

    def test_validation_is_read_only(self):
        # validate_daily_digest_for_archive_read()自体はvalidationのみを行い
        # disk書込みを一切行わない関数だが、本testでは念のためファイル内容
        # (mtime含む)が前後で変化しないことも確認する。
        for path in self.daily_digest_paths:
            with self.subTest(file=path.name):
                before_bytes = path.read_bytes()
                before_mtime = path.stat().st_mtime_ns
                document = json.loads(before_bytes.decode("utf-8"))
                daily_json.validate_daily_digest_for_archive_read(document)
                after_bytes = path.read_bytes()
                after_mtime = path.stat().st_mtime_ns
                self.assertEqual(before_bytes, after_bytes, f"{path.name}: 内容が変化しました")
                self.assertEqual(before_mtime, after_mtime, f"{path.name}: mtimeが変化しました")


if __name__ == "__main__":
    unittest.main()
