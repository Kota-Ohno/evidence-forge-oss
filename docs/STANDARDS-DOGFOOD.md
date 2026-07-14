# Real standards authoring dogfood

実行日: 2026-07-14
対象: Evidence Forge 6.3.0 private release candidate

公式一次資料4件を、既存の保持済みWeb captureとSQLite記録だけから再利用した。
ネットワーク再取得は行わず、次の流れを実CLIで確認した。

1. 画面からコピーした空白正規化済みqueryを`preview-citation`へ渡す。
2. 返されたsource-exact文字列が1件だけであることを確認する。
3. 同じqueryを`cite-web --query`へ渡し、Candidateだけを作る。
4. 既存packetを`inspect-packet-head`で観察する。
5. 観察とは別に、外部保存したJCS headを使って`verify-packet`を実行する。

## Results

| Source | Preview | Candidate | Packet head inspection | Independent packet verification |
| --- | --- | --- | --- | --- |
| [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/) | normalized whitespace、1件 | 作成 | embedded/computed一致 | verified |
| [W3C PROV-O](https://www.w3.org/TR/prov-o/) | normalized whitespace、1件 | 作成 | embedded/computed一致 | verified |
| [SLSA Provenance 1.2](https://slsa.dev/spec/v1.2/provenance) | 2改行を復元、1件 | 作成 | embedded/computed一致 | verified |
| [in-toto Attestation Framework](https://raw.githubusercontent.com/in-toto/attestation/main/spec/README.md) | 1改行を復元、1件 | 作成 | embedded/computed一致 | verified |

`preview-citation`の4出力はすべて
`networkAccessed=false`、`candidateCreated=false`、`evidenceCreated=false`だった。
続く`cite-web --query`は4件とも`EvidenceCandidate`を返し、SLSAとin-totoでは
query中の空白を保持表現内の改行へ戻したsource-exact selectorを作成した。

| Source | JCS packet head | Raw JSON file SHA-256 |
| --- | --- | --- |
| OpenTelemetry | `396c8b25e2d941a2e5db17d134be1384d2d2f33bd801a1b12e875627d2e0393a` | `556ef6f2a9a51f623028015cc577dfc213b3a6135da076fe2fc9e5b0ea912139` |
| W3C PROV-O | `eb0d4c7d23005686eed8dab8925e060b6aeba4a90ede2bbdafcc647b68e9c8e0` | `6c34aa0af5dc737e2871401feb5630e69c50b1f1813b4b7ae9e23a10b5d291f1` |
| SLSA | `8e5cc4256d825e10432d66ca2f001b515bfad553262fc3cdfb77b99c17580ddf` | `18bc4c0eecd393133d33be456d04fa32348fe09af2fb2ed33bc90f8e65cf87df` |
| in-toto | `ddfefee9b2c26d703ba2ce2967ea53d27376a6139f16543d410f044825046a88` | `ebadc5013cc924d169ef5ef09c5cfd6c43123be8305726bcb3fdfd5cec6f1a79` |

4件すべてでembedded headと再計算したJCS headは一致し、raw JSON digestとは異なった。
inspectionは明示的に`packetVerified=false`を返し、その後の外部head付き
`verify-packet`だけが`outcome=verified`を返した。したがって、head発見と検証の境界も
実データ上で混同なく維持された。

## Findings closed

- F1（citation authoringの手作業）: 長いSLSA/in-toto引用を短縮せず、画面由来queryから
  source-exact selectorを一意に作成できた。
- F2（JCS headとraw file digestの混同）: 1コマンドで両方を併記しつつ、inspectionを
  verificationとして扱わない契約を確認した。
- 新たな高優先度の摩擦、privacy leak、暗黙のnetwork access、Evidence自動昇格は
  観測されなかった。
