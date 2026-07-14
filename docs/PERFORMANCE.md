# Performance checks

## Maximum lineage benchmark

`pnpm benchmark:max-lineage` は、製品の公開上限を実データ経路で検証する
repository checkout専用ベンチマークです。安定比較には3回の中央値を返す
`pnpm benchmark:max-lineage:stable` を使います。`--samples` は1–5だけを受け付けます。

- 100個の異なるローカルsourceをcaptureし、明示的にEvidenceへ昇格する
- 100個のportable packetを作る
- 1 packetのcollectionから開始し、1件ずつappendして99 transitionを保持する
- 10 / 25 / 50 / 100 packet地点でlineageを外部head付きで完全に再検証する
- 101件目が `PACKET_INDEX_FULL` で拒否されることを確認する
- 成否にかかわらずprivate temporary directoryを削除する

実行結果はpath、source本文、candidate/Evidence ID、digestを含まないJSONです。
時間は端末・Node.js・OS・負荷に依存するため、正しさと上限拒否のみをgateにし、
固定時間の合否判定は設けません。

### 2026-07-14 three-sample median baseline

Apple silicon / macOS / Node.js v26.0.0での参考値です。

| 項目 | 結果 |
| --- | ---: |
| packet / transition | 100 / 99 |
| 最終lineage | 552,876 bytes |
| fixture生成 | 45.59 ms |
| 初期lineage生成 | 59.48 ms |
| 2件から100件までの逐次append | 5,113.28 ms |
| 最終lineage完全再検証 | 41.40 ms |
| 101件目の拒否確認 | 38.58 ms |
| 全体 | 5,376.20 ms |
| 最大RSS（3 sampleを実行したprocess全体） | 179,312 KiB |

| packet / transition | lineage bytes | 累積append | 完全再検証 |
| --- | ---: | ---: | ---: |
| 10 / 9 | 55,976 | 94.18 ms | 4.68 ms |
| 25 / 24 | 138,793 | 434.80 ms | 10.66 ms |
| 50 / 49 | 276,818 | 1,461.51 ms | 20.64 ms |
| 100 / 99 | 552,876 | 5,113.28 ms | 41.40 ms |

逐次appendは、各時点の現在lineageを完全検証してから次を作るため、件数に応じて
累積処理量が増えます。一方、完全再検証時間とartifact sizeは各checkpointで概ね件数に
比例しています。将来比較では同じ端末・同じNode.js major・低負荷状態でstable commandを
実行し、中央値同士を比較します。絶対時間はmachine-dependentなので自動合否には使いません。

### Relative regression check

同一Node.js major・OS・architectureのstable結果を2つ保存し、相対比較できます。

```bash
pnpm benchmark:max-lineage:stable > baseline.json
# 比較対象のrevisionへ移動し、同じ端末・低負荷状態で実行
pnpm benchmark:max-lineage:stable > candidate.json
pnpm benchmark:compare baseline.json candidate.json
```

既定では、累積appendまたは完全再検証がbaselineの1.25倍を「最終checkpoint」または
「2つ以上のcheckpoint」で超えるとexit 2の `regressed` になります。短い初期checkpoint
1点だけの揺らぎは記録しつつ合否には使わず、`--max-ratio 1.5` のように1–3の範囲で変更できます。
3 sample未満、runtime familyの不一致、lineage sizeの変化、壊れた入力は性能比較せずexit 1で
停止します。結果は入力pathや絶対時間を含まず、相対ratioだけを報告します。

repositoryの既定baselineは `benchmarks/max-lineage-darwin-arm64-node26.json` です。private
readiness receiptはbaselineとcandidate benchmarkのcanonical SHA-256を両方保持し、ratioが
どの2結果から得られたかをpathなしで固定します。別runtimeでは対応するstable baselineを
`--baseline` で明示し、暗黙に比較対象を置き換えません。

## Review list query (2026-07-14)

500 candidatesのreview一覧を同一端末・同一SQLite fixtureで3回測定しました。最新のpromotion
attemptをcandidateごとの追加queryではなく一覧SQLへ統合した結果です。

| fixture | before | after |
| --- | ---: | ---: |
| 1文字quote × 500 | 8.49–15.19 ms | 2.90–3.53 ms |
| 100,000文字quote × 500 | 122.56 ms | 117.52–120.24 ms |

小さい通常recordではN+1 query除去の効果が大きく、巨大recordではJSON parseとenvelope検証が
支配的です。詳細APIは一覧500件の全parseを廃止し、candidate IDのindexed lookup 1件だけを
行うため、古いcandidateが誤って404になる問題も同時に解消しています。

### Bounded summary projection

一覧専用のimmutable summary projectionをworkspace schema v4で追加し、巨大なcandidate JSONを
一覧表示のたびに読まない構成へ変更しました。詳細取得は引き続き完全なcandidate envelopeを
検証します。同じ500 candidates・100,000文字quote・warm readの3 sampleでは、中央値が
116.44 msから9.83 msへ短縮しました（約91.6%）。一覧quoteはUnicode code point単位で最大240文字、
詳細quoteは無加工です。

JSON fieldだけをSQLで直接射影する案も測定しましたが、中央値172.54 msへ悪化したため破棄しました。

## Private readiness orchestration (2026-07-14)

repository checkでbuild済みのartifactをpacked install smokeが再packする際、`prepack`の重複buildを
無効化しました。同一の10段階full readinessを3 sampleずつ測定した参考値です。

| revision | samples | median |
| --- | --- | ---: |
| before | 53.09 / 50.98 / 53.49 s | 53.09 s |
| after | 52.88 / 51.37 / 50.75 s | 51.37 s |

中央値は約3.2%短縮です。packed install smoke（約20–23秒）とmaximum-lineage benchmark
（約18秒）が実検証時間の大半を占めるため、これらを省略・並列化してbenchmark条件を崩す変更は
行っていません。計測中、relative comparisonが許容する単一checkpointの揺らぎをreceiptだけが
拒否する不整合も発見し、receiptをcomparison gateの最終判定に一致させました。
