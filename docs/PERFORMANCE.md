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
pnpm benchmark:compare -- baseline.json candidate.json
```

既定では、どのcheckpointでも累積appendまたは完全再検証がbaselineの1.25倍を超えると
exit 2の `regressed` になります。`--max-ratio 1.5` のように1–3の範囲で変更できます。
3 sample未満、runtime familyの不一致、lineage sizeの変化、壊れた入力は性能比較せずexit 1で
停止します。結果は入力pathや絶対時間を含まず、相対ratioだけを報告します。

repositoryの既定baselineは `benchmarks/max-lineage-darwin-arm64-node26.json` です。private
readiness receiptはbaselineとcandidate benchmarkのcanonical SHA-256を両方保持し、ratioが
どの2結果から得られたかをpathなしで固定します。別runtimeでは対応するstable baselineを
`--baseline` で明示し、暗黙に比較対象を置き換えません。
