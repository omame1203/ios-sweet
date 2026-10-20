# POCO PadへのiPadOS移植（作業中）

対象はPOCO Pad 2405CPCFBG（`dizi`、SM7435）。
参考実装のRedmi Note 10 Pro（`sweet`、SM7150）とは別の機種です。
**実機でiPadOSのロック画面とホーム画面の表示を確認済みです。**
ホーム画面到達には診断用HID Homeイベントを使用しました。0099実機試験では物理電源ボタンの動作をユーザーが確認（反応は遅い）。音量ボタンとタッチは引き続き検証中です。

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
  パッチ0097を組み込んだXNUでも、ユーザーの実機ログで `iOSRoot` のHFSマウントとlaunchd実行試行を確認。
  launchdの終了理由 `EXEC/WRONG_PLATFORM` を特定し、参照実装の起動引数で先へ進みました。
  保存ログを回収し、SpringBoardがLaunchServicesのデータベース初期化を待っていると特定。
  その先でMobileGestaltがネットワークMAC情報を待っていました。保存済みの実機Wi-Fi MACを
  ADTの `wlan/local-mac-address` に渡すことで進み、2026-10-21の実機写真でロック画面を確認。
  これは識別情報の公開で、Wi-Fi通信ドライバーの実装ではありません。
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
- Novatek NT36532のタッチ報告（108バイト、最大10点）をHIDに変換するパッチ0100を追加。
  ホスト上でARM64コンパイルと報告パーサの境界検査が通過。現在の実機設定はSPI FIFO無効のため、
  実タッチを動作させるにはGPI DMAリングとIOMMUアドレス変換の移植が必要です。
  診断06〜13では静的GPII0とapps SMMUの読み取りに実機で成功。GPII0リングは未割り当て状態と整合し、
  現行SMMUにはタッチ用SID 0x416/0x403のSMR一致がなく、未一致をフォルトにする設定を確認しました。
  GPI DMA実行はSMMUドメインの正しい設定が実装されるまで保留します。
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
python3 tools/mkadt.py shim/out/dizi/dizi-ipad5-wlan.adt --board dizi \
  --wlan-mac-file research/ipad5/dizi-wlan-mac.bin
# 実際のiPadOSルートを使うペイロード（起動引数をボード設定から取得）:
python3 tools/mkpayload.py xnu/out-0098/kernel.development.sweet \
  shim/out/dizi/dizi-ipad5-wlan.adt shim/out/dizi/payload-ipados.bin --board dizi
python3 tools/validate-repo.py
python3 tools/dizi-diag.py --out logs/dizi-diag.txt   # Android復帰を利用するため、Android使用時のみ
# iPadOSルートに置換済みの場合、USBのみ回収してAndroidへの復帰を待たない
python3 tools/dizi-diag.py --no-android --image shim/out/dizi/shim-boot-input-probe06-static-gpi0.img --out logs/dizi-input-probe06.txt
```

`dizi-wlan-mac.bin` は保存したAndroid実機調査のWi-Fi MACを6バイトのバイナリにした非公開ファイルです。
MAC情報を省略すると、アプリ一覧の初期化待ちが再発する可能性があります。

機種情報の抽出元は `research/ipad5/j71sap.adt` です。Apple配布IPSWから取り出した実ファイルが必要です。
Appleファイル、実機デバイスツリー、バックアップ、ビルド生成物はGitに含めません。
バックアップを再採取するときは `--out` で新しい保存先を指定します。保存済みの内容は上書きしません。
取得元・正確なコマンド・ビルド状況は `NOTES.md` の先頭に記録しています。

残作業は、物理キーとタッチでのロック解除・ホーム画面の操作確認、
SM7435向けのNovatek SPIタッチ・PMICキー・USBドライバーの移植です。
参考実装のドライバーは初期試験で無効化します。
画面のstride・ピクセル形式はロック画面の実機表示で確認済みです。時刻・バッテリー値の正確さは未確認です。

userdataには承認を受けてiPadOSルートイメージを書き込み済みです。
Windows/ESP、ブートローダー、リカバリ、校正領域を保護し、追加の消去は行いません。
