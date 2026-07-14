# Evidence Forge operator runbook

install直後の最短確認は、外部入力を受け取らないoffline self-testです。

```bash
evidence-forge-self-test run
```

固定した非user fixtureだけをprivate temp内でcapture→promotion→portable packet検証し、packageの
capability registryも確認します。network workflow、SQLite、listenerは開かず、成功・失敗のどちらでも
temp rootを削除します。出力はpackage version、成功check、`networkAccessed: false`、
`databaseOpened: false`、`listenerOpened: false`、`temporaryBytesRetained: false`だけを含む閉じたsummaryです。
未知・余分な引数はpartial runとして`SELF_TEST_OPERATION_FAILED`で拒否します。

Evidence Forgeは、観測内容をそのままEvidenceにせず、保存済みソースのハッシュと
完全一致引用を検証してから昇格するローカル専用ツールです。通常運用では次の4段階
だけを扱います。

実ファイル1件からportable packetまでを最短で作る場合は、次の1コマンドを
使えます。

```bash
pnpm --silent forge \
  --source notes.txt \
  --exact-file ./private-exact.txt \
  --available-at 2026-07-13T00:00:00.000Z \
  --directory ./my-evidence \
  --promote-immediately
```

新しいprivate directory内にCandidate、VerifiedEvidence、portable packet、packet検証結果を
作り、stdoutにはpathとsource本文を含まない結果だけを返します。途中で失敗した場合はこの
コマンドが新規作成したdirectoryだけを削除し、入力sourceには触れません。
`--exact-file`は0600の非空UTF-8 regular file（最大64 KiB）をsymlink追跡なしで一度だけ読み、
引用文をforge process引数へ載せない推奨経路です。UTF-8 BOMとNULは拒否し、末尾改行を含む
他の内容は引用の一部です。literalをshell履歴へ残さないprivate editorか、
`umask 077; IFS= read -r -s exact; printf %s "$exact" > private-exact.txt; unset exact`
の対話入力で作成します。
互換用の`--exact TEXT`も残ります。`--silent`はpnpm自身による引数反射を防ぎます。
`--promote-immediately`はCandidate生成前に即時昇格を事前許可する指定です。この最短経路は
Candidate確認で一時停止しません。packageから使う場合は同じ引数で
`evidence-forge forge-local`を実行します。source checkoutの`pnpm forge` aliasは安全な
incremental stale-source checkを先に実行します。
昇格前にCandidateを人が確認する場合、複数件をSQLiteへ蓄積する場合、Review Workspaceを
使う場合は、以下の分離コマンドを使ってください。

## 1. Capture and promote

```bash
evidence-forge capture \
  --workspace .evidence-forge/objects \
  --source notes.txt \
  --exact "根拠として引用する原文" \
  --available-at 2026-07-13T00:00:00.000Z \
  --database .evidence-forge/workspace.sqlite \
  --out candidate.json

evidence-forge promote --candidate candidate.json \
  --database .evidence-forge/workspace.sqlite \
  --out evidence.json
```

`candidate.json`はEvidenceではありません。`promote`が保存済みソースを再検証し、
成功した場合だけ`VerifiedEvidence`を生成します。共通databaseにはcandidate、拒否された
試行、成功したEvidenceが追記され、後述のReview Workspaceからそのまま確認できます。
`--database`を省略すれば従来のfile-only運用になり、出力先は既存ファイルを上書きしません。

Webページを根拠にする場合も、取得と引用候補化を分離します。

```bash
evidence-forge capture-web \
  --workspace .evidence-forge \
  --url https://example.com/source \
  --database .evidence-forge/workspace.sqlite \
  --out web-capture.json

evidence-forge cite-web \
  --capture web-capture.json \
  --exact "保存済みレスポンスに一度だけ現れる原文" \
  --database .evidence-forge/workspace.sqlite \
  --out web-candidate.json

evidence-forge promote --candidate web-candidate.json \
  --database .evidence-forge/workspace.sqlite \
  --out web-evidence.json
```

画面からコピーした文章と保存済みHTMLの改行位置が異なる場合は、URLへ再アクセスせずに
canonical citation textを検索できます。

```bash
evidence-forge preview-citation \
  --capture web-capture.json \
  --database .evidence-forge/workspace.sqlite \
  --query "ページからコピーした特徴的な文章" \
  --out citation-preview.json

evidence-forge cite-web \
  --capture web-capture.json \
  --database .evidence-forge/workspace.sqlite \
  --query "ページからコピーした特徴的な文章" \
  --out web-candidate.json
```

`preview-citation`はdatabase内のcaptureとの完全一致、通常ファイル、size、hash、UTF-8、
HTML派生viewを再検証します。最初に完全一致、その後に空白だけを正規化した検索を行い、
出力する`matches[].exact`は常に実際の保存済みcitation textです。最大20候補だけを返し、
CandidateもEvidenceも作成しません。`cite-web --query`は候補がちょうど1件の場合だけ、同じ
source-exact文字列からCandidateを作成します。0件または複数件ではfail closedします。

`cite-web`はURLへ再アクセスせず、database内のcaptureと入力ファイルが完全一致すること、
保持済みdecoded snapshotが通常ファイルであること、サイズ・SHA-256・UTF-8、および引用が
一意であることを再検証します。同じcaptureと引用を再入力しても同じcandidate IDへ収束します。
`text/html`では、script・style等を除いた上限付きプレーンテキストを
`evidence-forge/html-text@1`でオフライン生成し、そのSHA-256と元HTMLのSHA-256を
candidate/Evidenceへ結び付けます。元のdecoded HTML bytesは置き換えず保持し、promoteと
Reviewのたびに同じ変換を再実行します。UTF-8以外のcharset、致命的な途中切れ、上限超過、
変換bindingの欠落・改変は確認不能として拒否します。
非公開アドレスは既定で拒否されます。信頼済みの社内・ローカル取得に限り、
`capture-web`へ`--allow-private-addresses`を明示してください。

Review WorkspaceではWeb由来の候補を一覧で区別し、詳細の「Web取得の記録」から
queryを除いた取得開始URL・最終URL、redirect回数、HTTP状態、取得日時、本文形式を
確認できます。この表示は保存済み本文を使うためWebへ再アクセスしません。対応する
captureが欠落・複数一致・不整合の場合は、ローカルパスを出さず確認不能として表示します。
HTML由来の引用文脈には「HTMLから派生」と表示し、表示本文と保持された原本bytesを区別します。

## 2. Sign and bundle

```bash
evidence-forge-sign-report --report report.json \
  --private-key signer-private.pem --out report.signature.json

evidence-forge-bundle-report --report report.json \
  --signature report.signature.json --public-key signer-public.pem \
  --out review.bundle.json
```

秘密鍵はEd25519 PKCS#8で、権限`0600`以下が必須です。bundleに秘密鍵やローカル
パスは入りません。複数署名では`--signature`と`--public-key`を繰り返します。
信頼anchorとして別経路で共有するkey IDは次のコマンドで導出します。

```bash
evidence-forge-key-id --public-key signer-public.pem
```

出力される`sha256-spki` key IDは公開鍵の識別子であり、それ自体が信頼を与える
ものではありません。期待値との照合はbundleを受け取る経路と分離してください。

複数のkey ID、threshold、失効、policy windowを手で転記せずに共有する場合は、
決定論的なtrust manifestを作ります。

```bash
evidence-forge-trust-manifest create-manual \
  --public-key signer-a-public.pem --public-key signer-b-public.pem \
  --signature-threshold 2 \
  --valid-until 2027-07-13T00:00:00.000Z \
  --out trust-manifest.json
```

表示されたmanifest SHA-256をbundleとは別の経路で共有し、受領側で全文fingerprintを
比較します。

```bash
evidence-forge-trust-manifest inspect --manifest trust-manifest.json \
  --expected-sha256 EXPECTED_MANIFEST_SHA256
```

## 3. Verify the handoff

```bash
evidence-forge-verify-review --stack-bundle review.bundle.json \
  --trust-manifest trust-manifest.json \
  --trust-manifest-sha256 EXPECTED_MANIFEST_SHA256 \
  --out verification-receipt.json
```

信頼するkey IDはbundleとは別経路で取得します。receiptは検証結果の改変検知記録であり、
元の署名、外部trust anchor、信頼できる時刻を置き換えるものではありません。
manifestを使わないraw key ID方式も互換性のため残ります。

## 4. Review locally

```bash
evidence-forge review --database .evidence-forge/workspace.sqlite \
  --stack-bundle review.bundle.json \
  --trust-manifest trust-manifest.json \
  --trust-manifest-sha256 EXPECTED_MANIFEST_SHA256
```

Review Workspaceは`127.0.0.1`だけで待ち受けます。終了は`Ctrl+C`です。鍵を更新する
場合は`evidence-forge-rotate-trust --help`で履歴方式を確認し、初期key ID・threshold・
最新`historySha256`をbundle外の独立した経路で固定してください。

すべてのコマンドは`--help`に対応し、失敗時は終了コード1を返します。CLIへ渡した
ローカルパスはエラー出力で`[local file]`に置換されます。

## Release provenance

release acceptanceのpackage・revision・bundle・manifest・receipt digestを一つの閉じた
statementへ固定するには`evidence-forge-provenance create --help`を使います。
`--private-key`を省略したstatementはJCS integrityのみ、省略しない場合はdomain-separated
Ed25519署名を持ちます。署名済みstatementの検証には、statementとは別経路で入手した
公開鍵と期待key IDの両方が必要です。

```bash
evidence-forge-provenance verify --statement provenance.json \
  --trusted-public-key provenance-signer-public.pem \
  --expected-key-id EXPECTED_PROVENANCE_SIGNER_SHA256
```

statementは時刻を持たず、`timestamp: not-attested`を必須にします。署名に成功しても、
作成時刻・公開時刻・第三者timestampを証明するものではありません。

## Durable release evidence pack

長期保管用packはpackage tarball、review bundle、trust manifest、verification receipt、
署名済みprovenance statement、公開鍵、検証schema、要約を一つの閉じたJSONへ格納します。

```bash
evidence-forge-release-pack create \
  --package evidence-forge.tgz --bundle review.bundle.json \
  --manifest trust-manifest.json --receipt verification-receipt.json \
  --statement provenance.json --provenance-public-key provenance-signer-public.pem \
  --out release.evidence-pack.json
```

表示されたpack SHA-256とprovenance signer key IDをpackとは別経路で保存し、source
repositoryがない環境でも全digest・署名・trust policyの連鎖を再検証します。

```bash
evidence-forge-release-pack verify --pack release.evidence-pack.json \
  --expected-pack-sha256 EXPECTED_PACK_SHA256 \
  --expected-provenance-key-id EXPECTED_PROVENANCE_SIGNER_SHA256

evidence-forge-release-pack extract --pack release.evidence-pack.json \
  --expected-pack-sha256 EXPECTED_PACK_SHA256 \
  --expected-provenance-key-id EXPECTED_PROVENANCE_SIGNER_SHA256 \
  --out new-empty-directory
```

展開は新規directoryだけを受け付け、固定名のfileを`0600`で作ります。任意path、symlink、
既存fileの上書きは扱いません。packは最大24 MiB、同梱packageは最大16 MiBです。
署名時刻は引き続きattestされないため、外部timestampの代替にはなりません。

## Archival release index

複数releaseを保管する場合、各packを検証してからpath-freeなappend-only indexへ追加します。
初回は`--current-index`を省略し、2件目以降は現在のindexと別経路で保管した期待digestを
必ず指定します。

```bash
evidence-forge-release-index append --pack release.evidence-pack.json \
  --expected-pack-sha256 EXPECTED_PACK_SHA256 \
  --expected-provenance-key-id EXPECTED_PROVENANCE_SIGNER_SHA256 \
  --current-index current-release-index.json \
  --expected-current-index-sha256 EXPECTED_CURRENT_INDEX_SHA256 \
  --out next-release-index.json

evidence-forge-release-index verify --index next-release-index.json \
  --expected-index-sha256 EXPECTED_NEXT_INDEX_SHA256
```

indexは最大256 release・256 KiBで、時刻を記録しません。各entryは前entryのSHA-256へ
連結し、release versionをSemVer順に単調増加させます。最新index digestの外部固定が
tail rollbackを防ぐため、packと同じ配送場所だけに置かないでください。index検証は
pack内容の再検証を代替せず、定期監査では対象packも`release-pack verify`で開きます。
また、index運用開始前のreleaseや一度も登録されなかったreleaseの存在は証明できません。

保管packを一括監査する場合は、同じindexに対応するpackをすべて繰り返し指定します。

```bash
evidence-forge-audit-archive audit \
  --index release-index.json --expected-index-sha256 EXPECTED_INDEX_SHA256 \
  --pack release-1.evidence-pack.json --pack release-2.evidence-pack.json \
  --out archive-audit-receipt.json
```

packの順序は問いません。indexにあるpackの欠落、indexにないpack、同一packの重複を
拒否し、一致した全packについてpackage digest、provenance署名、review署名、historical
trust policyを再検証します。最大256 packを逐次処理し、成功時だけpathやkey IDを含まない
`0600` receiptを作ります。receiptは監査結果の改変検知記録であり、署名・trusted timestamp・
外部index anchorの代替ではありません。

監査済みの保管範囲をReview Workspaceで確認する場合は、同じpinned indexとreceiptを
起動時に渡します。不一致や片方だけの指定は画面を開く前に拒否されます。

```bash
evidence-forge review --database workspace.sqlite \
  --release-index release-index.json \
  --release-index-sha256 EXPECTED_INDEX_SHA256 \
  --archive-audit-receipt archive-audit-receipt.json \
  --archive-audit-receipt-sha256 EXPECTED_AUDIT_SHA256
```

更新履歴の連続性を同じ画面で確認する場合は、外部固定した最新history headと、その
完全なbinding集合を確認したaudit receiptを4点セットで渡します。画面へ渡るのはrelease
範囲、確認済み更新回数、時刻が未証明である旨だけです。path、binding head、key IDは
browserへ送られません。

```bash
evidence-forge review --database workspace.sqlite \
  --upgrade-history-index upgrade-history.json \
  --upgrade-history-index-sha256 EXPECTED_HISTORY_SHA256 \
  --upgrade-history-audit-receipt upgrade-history-audit.json \
  --upgrade-history-audit-receipt-sha256 EXPECTED_UPGRADE_AUDIT_SHA256
```

4項目の一部だけを指定した場合、期待digestが異なる場合、indexとreceiptの件数・範囲・
headが一致しない場合はlistener起動前にfail closedします。未指定時は、必要な記録を案内する
中立状態を表示します。画面表示は監査証跡そのものではないため、元index、全binding、audit
receipt、独立保管した2つの期待digestは引き続き保管してください。

signed packに入った配布版CLIでこの境界をまとめて再現する場合は、次を使います。

```bash
pnpm acceptance:upgrade-workspace \
  --release-pack release.evidence-pack.json \
  --release-pack-sha256 EXPECTED_PACK_SHA256 \
  --release-key-id EXPECTED_PROVENANCE_KEY_ID \
  --release-index release-index.json \
  --release-index-sha256 EXPECTED_RELEASE_INDEX_SHA256 \
  --archive-audit-receipt archive-audit.json \
  --archive-audit-receipt-sha256 EXPECTED_ARCHIVE_AUDIT_SHA256 \
  --upgrade-history-index upgrade-history.json \
  --upgrade-history-index-sha256 EXPECTED_HISTORY_SHA256 \
  --upgrade-history-audit-receipt upgrade-history-audit.json \
  --upgrade-history-audit-receipt-sha256 EXPECTED_UPGRADE_AUDIT_SHA256 \
  --output upgrade-workspace-acceptance
```

commandはpack署名を検証して展開し、packageを`--ignore-scripts --offline`で一時installした後、
その配布版`evidence-forge review`だけをport 0の`127.0.0.1`へ起動します。総合APIをinstalled
schemaへ照合し、CSPと時刻未証明copyを確認してから終了します。さらに内部hashを再計算した
途中version差し替え、途中pack head差し替え、履歴遅延を別processでlistener起動前に拒否します。
成功時の`acceptance-receipt.json`は0600で、package・capability/schema・archive/history・
coverage・拒否matrixを1つのJCS SHA-256へ固定し、入力path、key ID、trusted timeを含みません。
`loadWorkspaceAcceptanceReceipt`へreceiptと外部保管した期待headを渡せば、元入力なしで
schema、unknown field、改変、期待head不一致を再確認できます。
pack内のsigned package codeを実行する境界であり、sandboxやmalware検査ではありません。

配布版CLIだけでreceiptを再確認する場合は、archiveやlistenerを開かず次を実行します。

```bash
evidence-forge-verify-workspace-acceptance verify \
  --receipt acceptance-receipt.json \
  --expected-receipt-sha256 EXPECTED_RECEIPT_SHA256
```

成功projectionはpackage version、release範囲・件数、receipt head、時刻未証明だけです。
automationでは`--error-format json`を加え、`WORKSPACE_RECEIPT_SCHEMA_INVALID`、
`WORKSPACE_RECEIPT_INTEGRITY_INVALID`、`WORKSPACE_RECEIPT_HEAD_MISMATCH`を判定してください。

人がReview Workspaceで確認する場合は、同じ2つのanchorを`review`へ渡します。

```bash
evidence-forge review --database review.sqlite \
  --workspace-acceptance-receipt acceptance-receipt.json \
  --workspace-acceptance-receipt-sha256 EXPECTED_RECEIPT_SHA256
```

receiptだけならpackage version・記録範囲・件数を限定表示します。release archiveとupgrade
historyも同時指定した場合、receipt内の4つのarchive/audit head、release範囲、件数を総合確認結果へ
完全照合し、不一致ならlistener起動前に拒否します。成功時は総合確認カードへ配布版受入記録の
検証済みmarkerを加えますが、元pack/archiveの再検証やtrusted timestampを意味しません。
browserへ渡るclosed contractは`schemas/review-workspace-acceptance.schema.json`です。
repositoryの`pnpm acceptance:upgrade-workspace`はreceipt生成後、配布版CLIだけでreceipt-onlyと
総合照合を再実行し、partial指定、誤receipt head、archive head差し替えもlistener起動前に拒否します。

release保管監査とupgrade履歴監査の両方を同時指定した場合、Review Workspaceは画面を開く前に
両indexの全列を照合します。archiveの隣接releaseごとにupgrade entryがちょうど1件あり、前後の
versionとpack SHA-256が両側で完全一致しなければなりません。件数と最初・最後だけが同じでも、
途中releaseまたはpack headが違えば拒否します。成功時は個別カード2枚を、範囲・release件数・
更新回数・時刻未証明だけを示す総合確認1枚へ置き換えます。

packet collectionの追加履歴を人が確認する場合は、履歴indexと監査receiptをそれぞれ外部固定した
SHA-256と一緒に渡します。

```bash
evidence-forge review --database review.sqlite \
  --packet-transition-history-index packet-transition-history.json \
  --packet-transition-history-index-sha256 HISTORY_INDEX_SHA256 \
  --packet-transition-history-audit-receipt packet-transition-history-audit.json \
  --packet-transition-history-audit-receipt-sha256 HISTORY_AUDIT_SHA256
```

4項目はall-or-nothingです。起動前に両fileのhead、履歴件数、最初・最新のbundle headとpacket件数、
両端のtransition receipt headを完全照合します。画面には追加回数と最初・最新のpacket件数だけを
常時表示し、bundle headは「照合値を表示」を開いた場合だけ表示します。path、packet内容、identityは
browserへ渡しません。この表示は元receipt集合の再監査でもtrusted timestampでもありません。

同時に`--evidence-packet-bundle`とその期待SHA-256を指定した場合、表示対象bundleのheadとpacket件数を
履歴の最新地点へ完全照合します。古い世代や別collectionの有効なbundleでもlistener起動前に拒否し、
一致時だけ「現在の記録」と「確認した追加」を1枚の総合カードで表示します。

current bundle、history index、audit receipt、全transition receiptを一つの持ち運び用artifactへまとめる場合は
`export-packet-collection-lineage`を使い、完成したlineage headを別channelで固定します。

```bash
evidence-forge export-packet-collection-lineage \
  --evidence-packet-bundle packet-collection.bundle.json \
  --evidence-packet-bundle-sha256 BUNDLE_SHA256 \
  --packet-transition-history-index packet-transition-history.json \
  --packet-transition-history-index-sha256 HISTORY_SHA256 \
  --packet-transition-history-audit-receipt packet-transition-history-audit.json \
  --packet-transition-history-audit-receipt-sha256 HISTORY_AUDIT_SHA256 \
  --receipt transition-1.json --expected-receipt-sha256 TRANSITION_1_SHA256 \
  --receipt transition-2.json --expected-receipt-sha256 TRANSITION_2_SHA256 \
  --out packet-collection.lineage.json
evidence-forge verify-packet-collection-lineage \
  --lineage packet-collection.lineage.json --expected-sha256 LINEAGE_SHA256
evidence-forge review \
  --evidence-packet-lineage packet-collection.lineage.json \
  --evidence-packet-lineage-sha256 LINEAGE_SHA256
```

lineageは最大196 MiBのnofollow regular fileです。current collectionと全transition receiptをメモリ内で
完全再監査し、historyの最新bundle head・packet countへ一致した場合だけ成功します。logical nameは
receipt digestから決まり、traversal、欠落、重複、順序違い、別historyからの差し替え、古いendpointを
拒否します。Reviewは現在のpacket一覧と既存の総合カードを再利用します。standalone出力の
`historyCollectionReaudited: true`は埋込record集合の再監査だけを意味し、元file、identity、trusted timeの
証明ではありません。

固定済みlineageを次の監査済みcollectionへ1世代進める場合は、current lineage、next bundle、両者を
結ぶtransition receiptの3つをそれぞれ外部headと一緒に指定します。

```bash
evidence-forge append-packet-collection-lineage \
  --current-lineage packet-collection.lineage.json \
  --current-lineage-sha256 LINEAGE_SHA256 \
  --next-bundle next-packet-collection.bundle.json \
  --next-bundle-sha256 NEXT_BUNDLE_SHA256 \
  --transition-receipt next-transition.json \
  --transition-receipt-sha256 NEXT_TRANSITION_SHA256 \
  --out next-packet-collection.lineage.json
```

3入力を完全検証した後、current内のcollectionとnext bundleからexact append receiptを再計算して指定
receiptへ照合し、history chainと全receipt監査をメモリ内で更新します。既存history entryとtransition
recordは同一のままです。stale head、無関係・逆向き・重複transition、件数/容量上限、既存outputを
拒否し、current lineage、next bundle、receiptはいずれもbyte-for-byte変更しません。

next bundleとtransition receiptをまだ作っていない場合は、固定済みpacketをlineageへ直接追加できます。

```bash
evidence-forge append-packets-to-collection-lineage \
  --current-lineage packet-collection.lineage.json \
  --current-lineage-sha256 LINEAGE_SHA256 \
  --packet next.packet.json --expected-packet-sha256 NEXT_PACKET_SHA256 \
  --packet another.packet.json --expected-packet-sha256 ANOTHER_PACKET_SHA256 \
  --out next-packet-collection.lineage.json
```

lineageを一度完全検証し、packetを指定順に追加して、next collection、exact transition、history entry、
全receipt監査、outer headをメモリ内で導出します。next bundleやtransition receiptを個別fileへ書かず、展開や
中間fileもありません。anchor件数不一致、stale lineage、identity重複、件数/source/bundle/lineage容量超過、
既存outputを拒否し、lineageとpacket入力は変更しません。

2世代以上の実packをまとめて移行・監査するrelease rehearsalには
`pnpm acceptance:archive --help`を使います。各世代のpack SHA-256とprovenance signer
key IDを外部記録から明示し、古いindex prefixへのrollbackとpack欠落が拒否されることまで
確認します。

2世代間でlineageの実互換性を確認する場合は`pnpm acceptance:lineage --help`を使います。
older/newer pack、各pack head、provenance key IDを独立記録から指定します。両packageをscript無効・
offlineでinstallし、older CLIだけで作ったlineageをnewer CLIだけでverify・direct appendし、newerの
loopback Reviewまで確認します。出力receiptは両releaseとlineage endpoint、件数、不変性、stale
pack/lineage/packet headとoutput衝突の拒否をJCS headへ固定しますが、署名やtrusted timeではありません。

元packやlineageを再取得できない場合は、保管receiptと別channelに記録したheadだけを軽量確認できます。

```bash
evidence-forge-verify-lineage-continuity verify \
  --receipt acceptance-receipt.json \
  --expected-receipt-sha256 RECEIPT_SHA256
```

このcommandはreceiptのJCS integrity、release順序、pack/lineage headの分離、packet/transition件数の
進行、全checkがtrueであること、`timestamp: not-attested`を検証します。成功projectionの
`packsReexecuted: false`、`lineagesReaudited: false`、`timestampAttested: false`は、元packやlineageを
再実行・再監査していない境界を明示します。mutation、unknown/path field、stale head、同一・逆順release、
矛盾件数、false checkは安定codeで拒否されます。

同じ保管receiptを人が確認する場合は、Review Workspaceへ2つのanchorを渡します。

```bash
evidence-forge review --database review.sqlite \
  --lineage-continuity-receipt acceptance-receipt.json \
  --lineage-continuity-receipt-sha256 RECEIPT_SHA256
```

receiptはlistener起動前に検証されます。画面はrelease順序、lineage endpoint、packet/追加履歴件数、
receipt headだけを限定表示し、pack headや入力pathは受け取りません。「配布物を再実行していない」
「lineageを再監査していない」「確認時刻は第三者証明されていない」という限界も同じカード内に表示します。
未設定時は確認可能な記録がないことを説明し、partial指定、stale head、改変、逆順release、矛盾件数は
画面を開く前に拒否します。

保管receiptの到達点が現在のportable lineageそのものだと確認する場合は、上記2 anchorに
`--evidence-packet-lineage packet-collection.lineage.json`と
`--evidence-packet-lineage-sha256 LINEAGE_SHA256`も同時指定します。Reviewはlineageを完全検証した後、
receiptのnewer lineage head、packet件数、transition件数を現在値へ完全照合してからlistenerを開きます。
一致時は別々の成功表示ではなく「引き継ぎと現在の記録」の1枚に統合し、古い・別系統・件数遅れは拒否します。
loose bundle/historyはこの統合modeのlineage代替にはできません。receipt単体とlineage単体の表示は従来どおりです。

browserやdatabaseを開かずautomationから同じ到達点を確認する場合は、専用preflightを使います。

```bash
evidence-forge-preflight-lineage-continuity verify \
  --lineage packet-collection.lineage.json \
  --expected-lineage-sha256 LINEAGE_SHA256 \
  --receipt acceptance-receipt.json \
  --expected-receipt-sha256 RECEIPT_SHA256 \
  --error-format json
```

成功時はrelease順序、現在lineage/receipt head、現在のpacket/transition件数と限定的なassuranceだけを
閉じたJSONで返します。current lineageは完全再監査しますが元release packは再実行せず、trusted timeも
追加しません。schemaは`schemas/current-lineage-continuity-preflight.schema.json`です。

archive系CLIの失敗は`Release archive audit failed [ARCHIVE_PACK_MISSING]: ...`のように
安定diagnostic codeと人向け説明を返します。自動化は角括弧内のcodeを判定し、説明文へ
依存しないでください。codeは3–64文字の大文字英数字とunderscoreに限定され、入力pathは
従来どおり`[local file]`へ置換されます。未知の失敗でもCLIごとの
`*_OPERATION_FAILED` codeを返します。

安定code catalog:

- pack: `RELEASE_PACK_HEAD_MISMATCH`, `RELEASE_PACK_OPERATION_FAILED`
- index: `RELEASE_INDEX_ANCHOR_INCOMPLETE`, `RELEASE_INDEX_CHAIN_INVALID`,
  `RELEASE_INDEX_HEAD_MISMATCH`, `RELEASE_INDEX_INTEGRITY_INVALID`,
  `RELEASE_INDEX_PACK_DUPLICATE`, `RELEASE_INDEX_VERSION_NOT_INCREASING`,
  `RELEASE_INDEX_EMPTY`, `RELEASE_INDEX_OPERATION_FAILED`
- archive: `ARCHIVE_PACK_COUNT_INVALID`, `ARCHIVE_PACK_DUPLICATE`,
  `ARCHIVE_PACK_MISSING`, `ARCHIVE_PACK_UNEXPECTED`,
  `ARCHIVE_INDEX_METADATA_MISMATCH`, `ARCHIVE_RECEIPT_INTEGRITY_INVALID`,
`ARCHIVE_AUDIT_OPERATION_FAILED`
- current-lineage continuity: `PACKET_LINEAGE_HEAD_MISMATCH`,
  `LINEAGE_CONTINUITY_RECEIPT_HEAD_MISMATCH`, `LINEAGE_CONTINUITY_RECEIPT_INTEGRITY_INVALID`,
  `CURRENT_LINEAGE_CONTINUITY_HEAD_MISMATCH`, `CURRENT_LINEAGE_CONTINUITY_COUNT_MISMATCH`,
  `CURRENT_LINEAGE_CONTINUITY_OPERATION_FAILED`

すべてのCLIは、automation向けにcommand引数へ`--error-format json`を追加できます。失敗時はstderrへ
`version`, `kind`, `outcome`, `code`, `message`だけを持つ
`EvidenceForgeCliError`を1行で出力し、exit statusは非ゼロのままです。messageは入力pathを
redactし、UTF-8で4 KiB以下に切り詰めます。schemaは
`schemas/cli-error.schema.json`です。既定の人向けerror形式は変更しません。

installed packageのautomation契約を事前確認する場合は、次を実行します。

```bash
evidence-forge capabilities
```

出力はpackage version、全binary名、global error contract、同梱された全schemaの相対pathと
SHA-256を持つ決定的な`EvidenceForgeCliCapabilities`です。manifest自体もJCS SHA-256で
改変検知でき、schemaは`schemas/cli-capabilities.schema.json`です。local path、鍵、環境情報は
含みません。

HTML引用の派生viewは閉じた`schemas/citation-view.schema.json`に従い、capabilities出力が
そのSHA-256を固定します。candidate/Evidenceを読み込むpromotion、review、Sol Ledger exportは
TypeScript型を信頼せず、unknown field、null、別sourceのdigest、HTMLでのbinding欠落を拒否します。

candidate全体とVerifiedEvidence全体のportable契約は、それぞれ
`schemas/evidence-candidate.schema.json`と`schemas/verified-evidence.schema.json`です。
CLIの`promote`入力とSQLiteへの保存・読出しでは、top-levelだけでなくsnapshot、selector、
citation view、timestamp順序までruntime検証します。不正時の`INVALID_EVIDENCE_ENVELOPE`は
local pathや入力値をmessageへ含めません。

一件のverified citationを元workspaceなしで受け渡す場合は、次を実行します。

```bash
evidence-forge export-packet --candidate candidate.json --evidence evidence.json --out evidence-packet.json
evidence-forge inspect-packet-head --packet evidence-packet.json --out packet-head.json
evidence-forge verify-packet --packet evidence-packet.json --expected-sha256 PACKET_SHA256
```

`inspect-packet-head`は、packet内のJCS payload head、同じpayloadから再計算したhead、
整形済みJSONファイル全体のSHA-256を区別して表示します。regular file、size、閉じたpacket
構造は確認しますが、外部anchorとの照合、source bytesのdecode/hash、promotion replay、packet
検証、trusted timeの主張は行いません。表示したpacket headは別channelで固定するための候補であり、
検証結果ではありません。実際の検証には、別に保持したheadを`verify-packet`へ渡してください。

`schemas/evidence-packet.schema.json`はsource bytesをbase64で最大16 MiBまで保持し、logical nameを
`source.bin`、snapshot参照を`packet:source`とdigest URNへ固定します。export/verifyの両方で
promotion gateを再実行し、source hash、selector context、HTML citation view、candidate/Evidence
bindingを照合します。packet headは別channelで固定してください。timestampは`not-attested`です。

DBを作らず人が内容を確認する場合は、`evidence-forge review --evidence-packet
evidence-packet.json --evidence-packet-sha256 PACKET_SHA256`を実行します。packetと外部headは
listener起動前に検証され、databaseとの同時指定や片方だけの指定は拒否されます。画面は
元path/URIを表示せず、引用前後、Evidence ID、source hash、packet head、時刻未証明の限界だけを
表示します。API detailのclosed contractは`schemas/review-evidence-packet.schema.json`です。

複数packetを順序込みで固定して監査する場合は、次を実行します。

```bash
evidence-forge create-packet-index \
  --packet first.packet.json --expected-packet-sha256 FIRST_PACKET_SHA256 \
  --packet second.packet.json --expected-packet-sha256 SECOND_PACKET_SHA256 \
  --out packet-index.json
evidence-forge audit-packet-collection \
  --packet-index packet-index.json --packet-index-sha256 PACKET_INDEX_SHA256 \
  --packet first.packet.json --packet second.packet.json \
  --out packet-audit.json
```

index作成時はpacketごとに別channelで保持したheadを同じ順序で指定します。closed contractの
`schemas/evidence-packet-index.schema.json`は最大100件かつsource bytes合計64 MiBまでの
packet/source head、candidate ID、
Evidence IDをhash chainへ固定します。standalone auditはDBを開かず全packetを再検証し、欠落、
余分、重複、並べ替え、改変、metadata差し替えを拒否します。receipt contractは
`schemas/evidence-packet-collection-audit-receipt.schema.json`、timestampは`not-attested`です。

監査済みcollectionを人が検索・確認する場合は、index、audit receipt、全packetを同じ順序で
`evidence-forge review`へ渡します。

```bash
evidence-forge review \
  --evidence-packet-index packet-index.json \
  --evidence-packet-index-sha256 PACKET_INDEX_SHA256 \
  --evidence-packet-audit-receipt packet-audit.json \
  --evidence-packet-audit-receipt-sha256 PACKET_AUDIT_SHA256 \
  --evidence-packet first.packet.json \
  --evidence-packet second.packet.json
```

listenerはindex、receipt、全packetの一致を再確認した後にだけ起動します。画面は引用文を検索でき、
desktop/mobileとも一覧か詳細の一階層だけを表示し、packet pathや元source URIを返しません。

既存indexを作り直さず1件だけ追加する場合は、current index headと新packet headを別channelから
指定し、新しい出力先へappendします。

```bash
evidence-forge append-packet-index \
  --current-index packet-index.json \
  --current-index-sha256 PACKET_INDEX_SHA256 \
  --packet next.packet.json \
  --expected-packet-sha256 NEXT_PACKET_SHA256 \
  --out next-packet-index.json
```

current indexは変更されず、新index内でも既存entryは同一のまま末尾に1件だけhash-chain接続されます。
stale head、packet/candidate/Evidence ID重複、100件上限、source合計64 MiB超過、既存outputへの上書きは
拒否されます。新indexを利用する前に、全packetを指定した`audit-packet-collection`を再実行してください。

packet本体をまだ受け取っていない段階でindexとaudit receiptのbindingだけを軽量確認する場合は、
`verify-packet-collection`へ両artifactと外部headを指定します。出力は件数、source合計byte、
先頭/末尾packet head、index/audit head、`timestampAttested: false`だけです。source bytesの再検証を
代替しないため、packet入手後は必ずfull auditを実行してください。

index、audit receipt、全packetを単一fileで受け渡す場合は、
`export-packet-collection-bundle`でbundleを作り、そのheadを別channelで固定します。
`verify-packet-collection-bundle`は最大192 MiBのregular fileをnofollowで読み、digest由来logical name、
index/receipt binding、全packetのsource・selector・Evidence、順序、bundle headを展開せず再検証します。
`review --evidence-packet-bundle ... --evidence-packet-bundle-sha256 ...`も同じ検証をlistener起動前に
完了し、元path/URIを表示しません。timestampは引き続き`not-attested`です。

既存bundleへpacketを1件以上追加する場合は、current bundle headと各packet headを別channelから
固定し、current bundleを一度だけ検証して、展開・中間fileなしで新しいbundleを作ります。

```bash
evidence-forge append-packet-collection-bundle \
  --current-bundle packet-collection.bundle.json \
  --current-bundle-sha256 BUNDLE_SHA256 \
  --packet next.packet.json \
  --expected-packet-sha256 NEXT_PACKET_SHA256 \
  --packet another.packet.json \
  --expected-packet-sha256 ANOTHER_PACKET_SHA256 \
  --out next-packet-collection.bundle.json
```

各`--packet`は指定順に1つの`--expected-packet-sha256`と対応します。current bundleと全packetを
完全検証してから、既存index entryとpacket recordをそのまま保持し、指定順の末尾entry、全packet
対応audit receipt、bundle headを再計算します。anchor件数不一致、stale head、既存またはbatch内の
identity重複、100件・source合計64 MiB・bundle 192 MiBの上限超過、既存outputへの上書きを拒否し、
current bundleはbyte-for-byte変更しません。

2つのbundleが正確なappend関係にあることを独立監査する場合は、両bundleと外部headを指定します。

```bash
evidence-forge audit-packet-collection-bundle-transition \
  --previous-bundle packet-collection.bundle.json \
  --previous-bundle-sha256 PREVIOUS_BUNDLE_SHA256 \
  --next-bundle next-packet-collection.bundle.json \
  --next-bundle-sha256 NEXT_BUNDLE_SHA256 \
  --out packet-collection-transition-audit.json
```

両bundleを完全検証し、全既存index entryとpacket recordが同一で、nextが1–99件を順序どおり
追加した場合だけclosed receiptを作ります。receiptは両bundle/index head、前後件数、追加sequence
範囲と先頭/末尾packet headだけを保持し、pathを含まず、timestampは`not-attested`です。

両bundleが手元にない段階でretained transition receiptだけを軽量確認する場合は、receiptと外部headを
指定します。

```bash
evidence-forge verify-packet-collection-transition \
  --receipt packet-collection-transition-audit.json \
  --expected-sha256 TRANSITION_AUDIT_SHA256
```

出力は前後bundle head、件数、追加sequence範囲、先頭/末尾packet headを含むpath-free projectionです。
`bundlesReaudited: false`と`timestampAttested: false`により、bundle内容の再監査やtrusted timeを
主張しません。mutation、unknown field、stale head、逆転range、件数不整合は拒否します。

複数のtransition receiptを一本の連続履歴として固定する場合は、receiptと各外部headを順序どおり
指定してhistory indexを作ります。既存historyには新しいoutputへ1件ずつappendできます。

```bash
evidence-forge create-packet-transition-history \
  --receipt transition-1.json --expected-receipt-sha256 TRANSITION_1_SHA256 \
  --receipt transition-2.json --expected-receipt-sha256 TRANSITION_2_SHA256 \
  --out packet-transition-history.json
evidence-forge append-packet-transition-history \
  --current-index packet-transition-history.json --current-index-sha256 HISTORY_SHA256 \
  --receipt transition-3.json --expected-receipt-sha256 TRANSITION_3_SHA256 \
  --out next-packet-transition-history.json
```

隣接receiptのbundle head、index head、packet countがすべて一致する場合だけhash-chain接続します。
gap、rollback、fork、重複、順序違い、stale head、既存outputへの上書き、99 transition超過は拒否され、
current indexは変更されません。indexはpacket内容、path、identity、trusted timeを保持しません。

history indexに対応するreceipt集合が完全かつ正しい順序で揃っていることを監査する場合は、indexの
外部headと全receiptを指定します。

```bash
evidence-forge audit-packet-transition-history \
  --index packet-transition-history.json --index-sha256 HISTORY_SHA256 \
  --receipt transition-1.json --receipt transition-2.json \
  --out packet-transition-history-audit.json
```

各receiptをbounded self-verificationした後、index内のheadとbundle/index/count projectionへ順番どおり
照合します。欠落、余分、重複、順序違い、mutation、別historyからのreceiptは拒否します。closed
audit receiptはhistory head、件数、初期/最新bundle head、初期/最新packet count、両端transition headを
保持し、pathやtrusted timeを含みません。

historyやtransition receiptが手元にない段階でretained audit receiptだけを確認する場合は、audit
receiptと外部headを指定します。

```bash
evidence-forge verify-packet-transition-history-audit \
  --audit-receipt packet-transition-history-audit.json \
  --expected-sha256 HISTORY_AUDIT_SHA256
```

projectionはhistory head、coverage両端、件数、両端transition headを返し、
`collectionReaudited: false`と`timestampAttested: false`を明示します。mutation、unknown field、
stale head、不可能な件数、同一endpoint bundle、transition endpoint不整合は拒否します。

upgrade前後のautomation契約をoffline比較する場合は、両manifestと独立保管したheadを
指定します。

```bash
evidence-forge compare-capabilities \
  --previous previous-capabilities.json \
  --expected-previous-sha256 EXPECTED_PREVIOUS_SHA256 \
  --current current-capabilities.json \
  --expected-current-sha256 EXPECTED_CURRENT_SHA256 \
  --out capability-compatibility-receipt.json
```

binary/schemaの追加はcompatible、binary/schemaの削除、既存schema digestの変更、error
contractの変更は保守的にbreakingです。compatibleはexit 0、breakingはreceiptを作成して
exit 2になります。receiptは最大64 KiB、`0600`、path/key IDなし、timestampは
`not-attested`です。schemaは
`schemas/capability-compatibility-receipt.schema.json`です。

連続する実release pack同士のupgrade rehearsalには
`pnpm acceptance:capabilities --help`を使います。各packの外部SHA-256とprovenance
signer key IDを指定し、署名・artifact bindingを再検証してから別々のclean-roomへinstallし、
newer packed CLIで比較します。v1.8→v1.9の実結果は、receipt schema追加に加えて既存
capability schemaをhardeningしたため、保守的に`breaking`です。head改ざんとsynthetic
binary削除も同じinstalled surfaceで拒否します。

`versionPolicy`はbreakingならmajor、binary/schema追加ならminor、差分なしならpatchを要求し、
実際のversion bumpと`satisfied`を記録します。exit statusは、compatibleかつpolicy適合なら0、
major bump済みでもbreakingなら2、version bump不足なら3です。つまりSemVer適合はconsumer
互換性を意味しません。pre-releaseと0.xを含め、このpolicyに例外は設けません。

両manifestとreceiptをinstalled packageなしで長期再検証できる一つの成果物へ固定するには、
各headを独立経路から取得して次を実行します。

```bash
evidence-forge-upgrade-evidence create \
  --previous previous-capabilities.json \
  --expected-previous-sha256 EXPECTED_PREVIOUS_SHA256 \
  --current current-capabilities.json \
  --expected-current-sha256 EXPECTED_CURRENT_SHA256 \
  --receipt capability-compatibility-receipt.json \
  --expected-receipt-sha256 EXPECTED_RECEIPT_SHA256 \
  --out upgrade-contract-evidence.json

evidence-forge-upgrade-evidence verify \
  --evidence upgrade-contract-evidence.json \
  --expected-evidence-sha256 EXPECTED_EVIDENCE_SHA256
```

成果物は最大640 KiB、`0600`、上書き禁止です。検証は埋め込まれた両manifest、receipt、
全cross-linkと外側のJCS SHA-256を再計算します。local path、key ID、作成時刻は保持せず、
timestampは`not-attested`です。schemaは
`schemas/upgrade-contract-evidence.schema.json`です。

upgrade evidenceを元release packのpackageへ結び付ける場合は、2つのpack head・provenance
signer key ID・upgrade evidence headを独立に取得して次を実行します。

```bash
evidence-forge-bind-upgrade create \
  --previous-pack previous.evidence-pack.json \
  --expected-previous-pack-sha256 EXPECTED_PREVIOUS_PACK_SHA256 \
  --expected-previous-key-id EXPECTED_PREVIOUS_PROVENANCE_KEY_ID \
  --current-pack current.evidence-pack.json \
  --expected-current-pack-sha256 EXPECTED_CURRENT_PACK_SHA256 \
  --expected-current-key-id EXPECTED_CURRENT_PROVENANCE_KEY_ID \
  --upgrade-evidence upgrade-contract-evidence.json \
  --expected-upgrade-evidence-sha256 EXPECTED_UPGRADE_EVIDENCE_SHA256 \
  --out release-upgrade-binding.json
```

両packの全署名・digestを再検証し、各packageを`npm --offline --ignore-scripts`で一時install
して、installed `capabilities`出力が埋込manifestと完全一致する場合だけ`0600` receiptを
作ります。install lifecycleは実行しませんが、packageの`capabilities` binary自体は実行します。
これはsandboxではなく、署名済みpackage codeを信頼して実行する境界です。receiptはpath、key ID、
時刻を保持せず、この境界を`packageCodeExecution: capabilities-binary`として明記します。
schemaは`schemas/release-upgrade-binding-receipt.schema.json`です。

複数世代のbinding receiptを連続履歴へ追加するには、初回はbindingだけ、2回目以降は現在の
indexと独立保管した期待headも指定します。

```bash
evidence-forge-upgrade-index append \
  --binding release-upgrade-binding.json \
  --expected-binding-sha256 EXPECTED_BINDING_SHA256 \
  --out upgrade-history-1.json

evidence-forge-upgrade-index append \
  --index upgrade-history-1.json \
  --expected-index-sha256 EXPECTED_CURRENT_INDEX_SHA256 \
  --binding next-release-upgrade-binding.json \
  --expected-binding-sha256 EXPECTED_NEXT_BINDING_SHA256 \
  --out upgrade-history-2.json
```

各entryは直前entry headをJCS SHA-256で参照し、隣接するversionと共有release pack headの
完全一致を要求します。gap、順序逆転、duplicate、改変は拒否します。正しい過去prefixへの
rollback検出には、常に最新index SHA-256をindex外で保持してください。最大256 entry・
256 KiB、`0600`、時刻なしです。schemaは`schemas/upgrade-history-index.schema.json`です。

保管したbinding receipt集合をpinned indexへ全件照合するには次を実行します。

```bash
evidence-forge-audit-upgrades audit \
  --index upgrade-history.json \
  --expected-index-sha256 EXPECTED_INDEX_SHA256 \
  --binding release-1-to-2.binding.json \
  --binding release-2-to-3.binding.json \
  --out upgrade-history-audit.json
```

missing、unexpected、duplicate receiptを拒否し、一致した全receiptのversion、両pack head、
upgrade evidence headをindexと再照合します。成功receiptは最大64 KiB、`0600`、path/key ID/
時刻なしです。schemaは`schemas/upgrade-history-audit-receipt.schema.json`です。

3世代以上のsigned release packからupgrade archive全体を再構築するrelease rehearsalは
`pnpm acceptance:upgrade-archive --help`で入力形式を確認します。各releaseについてpack、
外部pack SHA-256、provenance signer key IDを古い順に指定します。各隣接pairを別々にinstall・
比較し、upgrade evidence、release binding、hash-chained index、collection auditを生成します。
成功summaryはversion/count/headと`timestampAttested: false`だけを保持し、middle transition
omissionとvalid-prefix rollbackの拒否も同じ実artifactで検証します。
