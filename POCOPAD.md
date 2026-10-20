# POCO PadへのiPadOS移植（作業中）

対象はPOCO Pad 2405CPCFBG（`dizi`、SM7435）。
参考実装のRedmi Note 10 Pro（`sweet`、SM7150）とは別の機種です。
**iPadOSのカーネル起動・ホーム画面表示は未確認です。**

現在の構成は、既存のブートローダーから一時起動したshimがXNUを読み込む方式です。
Apple純正のUEFIをPOCO Padに書き込む方式ではありません。

実装済み：

- root端末からの読み取り専用調査と、ハッシュ検証付きブート・校正領域バックアップ。
- 実機FDTに照合できる `boards/dizi.json`。GIC・タイマー・CPU構成・RAM配置を分離。
- boot image v4形式のdizi用shim。既存のvendor_bootを使用。
- vendor ramdiskが先頭に付く場合にも対応したXNUローダーと境界検査。
- 起動時の画面情報を使うXNU初期コンソール、diziのプラットフォーム照合パッチ0082。
- Apple配布のiPadOS 16.7.16（20H392、iPad6,11）から作成した16GBのルートイメージとADT生成。
  実機の `/product` 情報を読み、1536×2048のiPad画面を1600×2560のパネル中央に置く設定。

確認済み：

- 19領域のバックアップを端末側SHA-256と照合。
- 最初の診断イメージは `fastboot boot` に受理され、その後Androidへ復帰。
  診断ログ未回収のため、GICやMMUが動作したとはまだ判定していません。
- ブートとvendor_bootの両スロットは一時起動前後でハッシュ一致。
- ローダー実装をASan・UBSan付きで検査。64種類の先頭オフセット、BSS・ADT・起動引数のコピー、
  不正なサイズ・オフセットの拒否を確認。
- 変更したXNUのC・アセンブリとプラットフォーム照合テーブルをARM64オブジェクトへコンパイル。
  画面サービスのC++変更は構文検査まで。完全なカーネルのリンク・起動は別途必要です。
- 元のsweet低位RAM・上位RAM・QEMU向けADTは、固定seedで元実装とバイト単位で一致。
- ルートイメージのHFS+検査、主要実行ファイルのARM64形式、共有キャッシュのリンク、初期設定、SHA-256を確認。

再現用コマンド（このフォルダで実行）：

```bash
export PATH="$PWD/../host-tools/platform-tools:$PATH"
python3 tools/pocopad-probe.py --backup
python3 tools/check-dizi-board.py backup/dizi/fdt
BOARD=dizi bash shim/build.sh
python3 tools/mkadt.py shim/out/dizi/dizi-ipad5.adt --board dizi
python3 tools/validate-repo.py
```

機種情報の抽出元は `research/ipad5/j71sap.adt` です。Apple配布IPSWから取り出した実ファイルが必要です。
Appleファイル、実機デバイスツリー、バックアップ、ビルド生成物はGitに含めません。
バックアップを再採取するときは `--out` で新しい保存先を指定します。保存済みの内容は上書きしません。
取得元・正確なコマンド・ビルド状況は `NOTES.md` の先頭に記録しています。

残作業は、完全なXNUのビルドとQEMU検証、実機での初期起動確認、
SM7435向けのNovatek SPIタッチ・PMICキー・USBドライバーの移植です。
参考実装のドライバーは初期試験で無効化します。
画面のstride・ピクセル形式も、予約領域とパネル寸法だけでは確定できないため実機確認が必要です。

Android、既存のWindows/ESP、ブートローダー、リカバリ、校正領域の消去は行っていません。
参考元のuserdata消去手順は、この端末にそのまま実行しないでください。
