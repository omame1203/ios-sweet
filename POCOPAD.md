# POCO PadへのiPadOS移植（作業中）

対象はPOCO Pad 2405CPCFBG（`dizi`、SM7435）。
参考実装のRedmi Note 10 Pro（`sweet`、SM7150）とは別の機種です。
**XNUの実機実行を確認済みです。iPadOSユーザー空間・ホーム画面の起動は未確認です。**

現在の構成は、既存のブートローダーから一時起動したshimがXNUを読み込む方式です。
Apple純正のUEFIをPOCO Padに書き込む方式ではありません。

実装済み：

- root端末からの読み取り専用調査と、ハッシュ検証付きブート・校正領域バックアップ。
- 実機FDTに照合できる `boards/dizi.json`。GIC・タイマー・CPU構成・RAM配置を分離。
- boot image v4形式のdizi用shim。既存のvendor_bootを使用。
- vendor ramdiskが先頭に付く場合にも対応したXNUローダーと境界検査。
- shimの起動ログをUSB EP0でライブ配信する診断transport（1209:0001）。
  ホスト側 `tools/dizi-usb-log.py` がリングを読み、`tools/dizi-diag.py` が
  一時ブートから回収までを自動化。
- 起動時の画面情報を使うXNU初期コンソール、diziのプラットフォーム照合パッチ0082。
- Apple配布のiPadOS 16.7.16（20H392、iPad6,11）から作成した16GBのルートイメージとADT生成。
  実機の `/product` 情報を読み、1536×2048のiPad画面を1600×2560のパネル中央に置く設定。

確認済み：

- UFSの読み取り失敗は、デバイスが準備されていない状態（sense `02/04/02`）と実測。
  診断shimでSTART STOP UNITによりACTIVEへ切り替えると、GPT・userdata・HFSX署名を読み取れました。
  同じ処理をXNUへ移すパッチ0097を準備済み。XNUからのルートマウント・ユーザーランド起動は別途検証します。
- 19領域のバックアップを端末側SHA-256と照合。
- 診断shimの実機画面を確認。GIC優先度設定時の例外は、アドレス自動更新なしのMMIO命令で通過。
  仮想タイマー終了時の `CNTP_CTL_EL0` 例外も、使用していない物理タイマーへのアクセスを除いて解消しました。
- 診断05の実機写真で、**仮想タイマー割り込み30回、SGI割り込み10回、その他の割り込み0回**、
  16KB MMU初期化 `rc=0`、イメージ・フレームバッファの変換検査、診断終了を確認。
  写真の数値・対応する一時起動イメージのハッシュは `NOTES.md` に記録。
- 診断shimのUSB診断を実機で確認。ホストが1209:0001をHSで列挙し、
  ディスクリプタ取得・SET_ADDRESS・SET_CONFIGURATIONの後、
  EP0経由で3,605バイトの起動ログを回収しました。ABLはstage-1 MMUを
  有効なまま渡すため、USB前にM/C/Iを明示的に落としています。ログと
  イメージのSHA-256は `NOTES.md` に記録。現在はuserdata書き換え後なので、
  Androidへの復帰は前提にせず、FASTBOOT接続を確認して一時起動します。
- ブートとvendor_bootの両スロットは一時起動前後でハッシュ一致。
- ローダー実装をASan・UBSan付きで検査。64種類の先頭オフセット、BSS・ADT・起動引数のコピー、
  不正なサイズ・オフセットの拒否を確認。
- GitHub Actionsで完全なARM64 XNUカーネルをリンク済み。実機で `IOFindBSDRoot` まで到達。
  USB初期化パニックは解消していますが、XNUのUSB列挙・通信はまだ成功していません。
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
python3 tools/dizi-diag.py --out logs/dizi-diag.txt   # Android復帰を利用するため、Android使用時のみ
```

機種情報の抽出元は `research/ipad5/j71sap.adt` です。Apple配布IPSWから取り出した実ファイルが必要です。
Appleファイル、実機デバイスツリー、バックアップ、ビルド生成物はGitに含めません。
バックアップを再採取するときは `--out` で新しい保存先を指定します。保存済みの内容は上書きしません。
取得元・正確なコマンド・ビルド状況は `NOTES.md` の先頭に記録しています。

残作業は、XNUからのUFSルートマウント、実際のlaunchd・SpringBoard起動、
SM7435向けのNovatek SPIタッチ・PMICキー・USBドライバーの移植です。
参考実装のドライバーは初期試験で無効化します。
画面のstride・ピクセル形式も、予約領域とパネル寸法だけでは確定できないため実機確認が必要です。

userdataには承認を受けてiPadOSルートイメージを書き込み済みです。
Windows/ESP、ブートローダー、リカバリ、校正領域を保護し、追加の消去は行いません。
