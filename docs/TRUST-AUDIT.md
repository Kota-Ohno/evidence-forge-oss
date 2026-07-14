# v1 trust-boundary audit

Evidence Forge v1は、ローカルのソース完全性・引用一致・署名quorumを検証しますが、
「誰を信頼するか」「その時刻を誰が保証するか」は自動決定しません。この文書は、
正式版の外側に残る信頼前提を明示したものです。

offline installed self-testは固定fixtureでlocal capture/promotion/packet/capability codeだけを通り、
network API、SQLite、listenerを呼びませんが、OS sandboxやmalware検査ではありません。
`networkAccessed: false`はこの限定code pathの主張であり、host上の別processや改変済みruntimeの通信を
監視・遮断した証明ではありません。temp削除に失敗した場合は成功summaryを返しません。

## Trust roots

| 境界 | Evidence Forgeが検証すること | Operatorが別経路で保証すること |
| --- | --- | --- |
| Source | 保存bytesのSHA-256と完全一致selector | 元ソースの真正性、ローカルcapture時に指定する`availableAt` |
| Web capture | public HTTP(S)応答bytes、redirect、取得metadata | 配信元そのものの正当性、公開時刻の意味 |
| Promotion | candidateが保存snapshotと一致し、必須metadataを持つこと | promotion ruleが用途に十分であること |
| Stack report | closed schema、JCS digest、4イベント、3 revision | Agent Black Box trusted headと各repository revisionの入手経路 |
| Signature | Ed25519署名、distinct signer、threshold、期限、revocation指定 | trusted key ID、threshold、期限、失効key IDの配布 |
| Bundle | report・署名・公開鍵の閉じた構造とJCS digest | bundle外から取得したtrust anchorとの照合 |
| Trust manifest | key ID・threshold・失効・windowの閉じた決定論的policyとJCS digest | manifest SHA-256をbundleとは独立した経路で照合すること |
| Rotation history | hash chain、旧quorum承認、単調な`effectiveAt`、期待head | 初期key ID/thresholdと最新`historySha256`の固定 |
| Receipt | 実行時に全検証が成功したこととreceiptのJCS digest | trusted timestamp、長期保存、元bundleとanchorの保持 |
| Provenance statement | package・3 revision・bundle・manifest・receipt headの閉じた結合と任意署名 | signer公開鍵/key IDの独立入手、statement外の公開時刻・第三者timestamp |
| Release evidence pack | package bytes・検証material・schema・要約の固定、全digest/署名のoffline再検証、安全な展開 | pack SHA-256とprovenance signer key IDの独立保管 |
| Release evidence index | release順序・pack/provenance期待値・前entry hash・index JCS digest | 最新index SHA-256の独立保管、定期的なpack本体の再検証 |
| Archive audit receipt | pinned indexとの集合一致、全packのdigest/署名/policy再検証、path-free JCS receipt | audit実行環境、index SHA-256の入手経路、trusted timestamp |

## Explicit non-guarantees

- SHA-256/JCS integrityはidentity signatureではありません。
- bundleに含まれる公開鍵はtransport materialであり、自分自身をtrust anchorに昇格できません。
- `evidence-forge-key-id`は公開鍵の識別子を正確に導出しますが、その鍵を信頼すべきかは判断しません。
- trust manifestは署名済みidentity statementではありません。期待SHA-256を同じ配送経路から取得すると独立anchorになりません。
- ローカル時計はtrusted time sourceではありません。期限・scheduled rotation・receipt時刻は実行端末の時計に依存します。
- 失効情報をネットワークから自動取得しません。`--revoked-key-id`または検証済みrotation historyをoperatorが供給します。
- `0600`とexclusive createは同一OS account内の誤操作を減らしますが、侵害済みhostや特権userから秘密鍵を守る保証ではありません。
- Review Workspaceは`127.0.0.1`だけで待ち受けますが、同一host上の他processやbrowser profile自体を信頼境界の外へ追い出すものではありません。
- provenance署名はstatementのauthorshipを検証しますが、`timestamp: not-attested`であり作成・公開時刻を保証しません。
- release evidence packの外部pack SHA-256は、同梱公開鍵・schema・要約を含む全内容を固定します。pack内のdigestだけを信頼せず、provenance signer key IDとともに独立経路で照合します。
- packのhistorical policy再検証はreceiptの`verifiedAt`との整合性を確認しますが、その時刻自体をtrusted timestampへ昇格しません。
- release evidence indexはpack検証結果を一覧化しますが、署名やtrusted timestampではありません。最新index digestを外部固定しない限り、有効な過去indexへのtail rollbackを単独では検出できません。
- indexが検出するomissionは、外部固定済みheadに含まれていたentryの削除です。運用開始前または未登録のreleaseが存在しないことは証明しません。
- archive audit receiptは成功した集合監査を要約しますが、署名されず時刻もattestしません。監査の真正性には元index・pack・外部anchorを保持してください。
- archive系diagnostic codeは失敗分類だけを表し、pathやkey IDを含みません。人向けmessageはpathをredactしますが、release versionなど非秘密の識別子を含む場合があります。
- `--error-format json`は同じredactionを適用しmessageを4 KiBに制限しますが、message内のrelease version等を秘密化するものではありません。automationはmessageでなくcodeを判定してください。
- capability manifestはinstalled package内のbinary/schemaを自己申告しdigestで改変検知しますが、配布物そのもののauthorshipは証明しません。packageまたはrelease packの外部anchorと組み合わせてください。
- capability compatibility receiptは2つの外部固定head間の構造差分であり、schemaの意味的後方互換性を証明しません。digest変更をbreakingへ倒し、timestampもattestしません。
- SemVer gateは構造差分に対する保守的release policyです。意味的互換性や利用側の移行成功を証明せず、major bump済みのbreaking変更も互換とは表示しません。
- real capability acceptanceはpack署名とartifact bindingを再検証しますが、npm registryや公開配布を使わず、指定されたlocal pack間だけを比較します。`--ignore-scripts`でinstall lifecycleを実行しません。
- upgrade contract evidenceは両manifestとreceiptの完全な再計算可能snapshotですが、外側の期待SHA-256を同じ配送経路から取得すると独立anchorにはなりません。署名・package authorship・schemaの意味的互換性・trusted timestampも追加しません。
- release upgrade bindingはpack署名とmanifest再現を結びますが、malware検査やsandboxではありません。install lifecycleとnpm network lookupは無効でも、外部anchorで信頼したpackageの`capabilities` codeを実行するため、signer trustと実行環境の隔離はoperator責任です。
- upgrade history indexはbinding receiptの連続性とomission/rollbackを可視化しますが、署名やtrusted timestampではありません。最新index headを外部固定しなければ、有効な過去prefixへのrollbackを単独では検出できません。
- upgrade history audit receiptはpinned indexとbinding集合の完全一致を要約しますが、元bindingの代替でも署名でもありません。再監査にはindex、全binding、外部index headを保持してください。
- cross-release upgrade acceptanceは複数世代の手順を自動合成しますが、新しいtrust sourceではありません。各pack head/key IDの独立入手、signed package codeの実行境界、最新history headの外部保管という既存条件はそのまま残ります。
- Review Workspaceの保管表示は、indexとaudit receiptの両方を外部期待digestへ照合してから有効になります。画面表示だけを監査証跡として扱わないでください。
- Review Workspaceの更新履歴表示も、history indexとaudit receiptを別々の外部期待digestへ照合し、件数・範囲・index headの一致を確認した要約です。画面は元binding、独立anchor、署名、trusted timestampの代替ではありません。
- packed upgrade-workspace acceptanceはsigned packを検証しても、配布packageの`capabilities`と`review` codeを実行します。`--ignore-scripts --offline`とloopback bindはinstall hookとnetwork取得を抑えますがsandboxではないため、provenance signerの信頼と隔離環境はoperator責任です。summaryも署名・trusted timestampではありません。
- archive/upgrade総合確認は両indexに含まれる全versionとpack headの位置対応を検証しますが、indexに登録される前のreleaseが存在しないことや、外部anchor自体の配送経路は証明しません。総合表示も元pack、binding、index、audit receiptの代替ではありません。
- packed workspace acceptance receiptは実行結果と入力headをJCS SHA-256へ固定しますが、署名やtrusted timestampではありません。期待receipt headを独立保管しない限り、別の自己整合したreceiptへの置換は検出できず、元pack/index/auditの再検証も代替しません。
- standalone workspace receipt verifierはreceiptだけをoffline検証し、元archiveを開かずlistenerも起動しません。この限定性は安全な再確認境界ですが、receipt作成時のsigned package code実行や元証拠の真正性を再実行するものではありません。
- Review Workspaceの受入記録markerは、外部固定receipt headと、同時設定されたarchive/history head・範囲・件数の一致だけを表示します。画面上のmarkerもreceipt自体の署名、元packの再実行、時刻証明を追加しません。
- Review Workspaceのpacket追加履歴表示は、外部固定した履歴indexと監査receiptを起動前に完全照合した限定projectionです。元transition receipt集合やbundle内容を再監査せず、path、packet内容、identity、trusted timestampも追加しません。
- 現在のpacket collection bundleと追加履歴の総合表示は、bundle headとpacket件数が履歴の最新地点へ一致することだけを追加確認します。履歴以前のbundle内容やtransition receipt集合を再監査するものではありません。
- Portable collection lineageのstandalone検証は、単一artifact内のcurrent bundleとtransition receipt集合を展開せず完全再監査し、historyの最新endpointへ一致させます。ただし外部固定したlineage headが必須であり、埋込前の元file、作成者identity、第三者署名、trusted timestampを証明しません。Review Workspaceは互換性のためM102の保守的な総合表示を再利用し、より強い再監査表示を追加しません。
- Lineage appendはcurrent lineage、next bundle、transition receiptの外部headをすべて要求し、2つのcollectionからexact appendを再計算してから新しいlineageだけをexclusive作成します。入力を更新しませんが、新lineage headの独立保管、作成者認証、trusted timestampを代替しません。
- Direct packet-to-lineage appendはnext bundleとtransition receiptを中間fileに残さず同じbindingを導出します。各packet headとcurrent lineage headを独立に取得する必要があり、完成したlineage headを別channelへ保管する責務や署名・時刻証明は変わりません。
- cross-release lineage acceptanceはolder/newer signed packを展開して同梱codeを実行する互換性rehearsalです。sandboxやmalware検査ではなく、pack head/key IDの独立入手が必要です。receipt integrityはlocal mutation検出であり、署名・trusted timestamp・packの再検証を追加しません。
- retained lineage-continuity receipt verifierはreceiptの外部head、release順序、endpoint/count進行、全checkを再計算しますが、元release packを再実行せずlineageも再監査しません。成功projectionはこの限定性とtrusted timestamp不在を明示し、receipt headをreceiptと同じchannelから取得した場合の自己置換も防ぎません。
- Review Workspaceのlineage continuity表示も同じreceipt-only境界です。listener起動前のfail-closed検証とpath-free表示を追加しますが、pack署名の再検証、lineage内容の再監査、receipt作成者の認証、trusted timestampは追加しません。
- continuity receiptとportable lineageを同時指定した総合表示は、lineageを完全検証したうえでnewer lineage head・packet件数・transition件数の一致を追加確認します。これはretained receiptが現在のartifactへ到達したことの整合確認であり、元release packの再実行、receipt署名、作成者認証、trusted timestampを追加しません。loose bundle/historyとの組み合わせはlineage identityを証明できないため拒否します。
- current-lineage continuity preflightは同じ整合確認をlistener/databaseなしで実行し、portable lineage内のcollection・history・transition集合を完全再監査します。ただしreceiptが参照する元release packの再実行や署名検証は行わず、receipt headとlineage headを同じchannelから取得した場合の自己置換、作成者認証、trusted timestampも解決しません。
- signed statementを要求する場合、検証時に外部公開鍵と期待key IDを必ず指定します。integrityだけのunsigned検証は、元のstatementが署名済みだったことを証明しません。

## Release acceptance

正式版候補は次をすべて満たす必要があります。

1. Evidence Forge、Agent Black Box、Sol Ledgerのworktreeがすべてcleanである。
2. cleanなEvidence Forge revisionからtarballを作り、そのSHA-256を結果へ記録する。
3. 空のconsumer projectへtarballをinstallし、repositoryの`dist`を直接importしない。
4. installed `evidence-forge`をAgent Black Boxでwrapし、Sol Ledgerで4イベントのtrusted headを検証する。
5. installed key-ID、sign、bundle、verify CLIだけでdistinct 2-of-2 receiptを作る。
6. bundleとreceiptが`0600`で、private key、local path、receipt内のraw key IDを保持しない。
7. installed release-pack CLIだけでpackを作成・再検証・固定名展開できる。
8. installed release-index/audit CLIだけでpinned indexを作り、pack集合の完全一致と全署名を再検証できる。

再現コマンド:

```bash
pnpm --silent acceptance:packed -- \
  --agent-black-box ../agent-black-box \
  --sol-ledger ../sol-ledger-protocol \
  --output .evidence-forge/packed-v1-audit
```

成功結果はpackage SHA-256、3製品のclean revisionに基づくstack report、bundle、manifest、
receipt、署名済みprovenance statement、release evidence packの各SHA-256をまとめます。
公開判断時にはpack本体と、pack外の期待digest・provenance signer key IDを別経路で保管します。
