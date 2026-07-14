# Pre-publication readiness audit

監査日: 2026-07-14

対象: private repositoryの現在のworking tree

結論: **公開操作は未実施。重大・高・中severityの公開阻害要因は未検出。**

実際にpublic化する直前には、対象commitを固定したうえで本書のコマンドを再実行し、
利用可能な専用secret scannerでも履歴とworking treeを再走査します。

## Findings

### Resolved — 専用secret scanner

- Evidence: Gitleaks 8.30.1でGit履歴とworking treeの両方を完全redaction付きで走査し、
  finding 0で完了した。
- Durable check: `pnpm audit:secrets` は専用scannerがない環境を成功扱いせず、履歴と現在treeの
  どちらかにfindingがあれば非zeroで停止する。report fileやsecret本文は出力しない。
- Follow-up: public化直前の固定commitで同じcommandを再実行する。

### Low — LICENSEに権利者名を表示する

- Evidence: `LICENSE` はcopyright holderとして `Kota Ohno` を記載する。
- Assessment: ライセンス上の通常の表示で、repository ownerとも整合する。secretではないが、
  public化すると恒久的に外部から参照可能になる。
- Follow-up: public化の最終確認時に、意図した公開名であることを確認する。

## Secrets and repository hygiene

- `.env*`、PEM/key、database、archive、`HANDOFF.md` は追跡されていない。
- `.gitignore` は `.evidence-forge/`、`work/`、`HANDOFF.md`、build/dependency出力を除外する。
- 実token形式、AWS access key形式、GitHub token形式、OpenAI key形式、private key headerは
  Git履歴・working treeとも未検出。
- GitHub Actionsのsecret値やローカル認証情報をREADME、fixture、画像へ埋め込んでいない。

## Privacy

- 追跡画像 `docs/assets/review-workspace.jpg` を目視確認。架空の製品fixtureとdigestのみで、
  氏名、メール、アカウント、ローカルpath、実URLは含まない。
- `/Users/private/...` はpath非露出を検証するunit test専用の合成値。
- README/OPERATORの外部URLは `example.com`。Review Workspaceはloopbackへbindする。
- package artifactと主要verification projectionはpath-freeをテストしている。

## Dependencies, legal, and assets

- project licenseはMITで、`LICENSE` と `package.json` が一致する。
- production dependencyは `parse5` (MIT) とtransitive `entities` (BSD-2-Clause)。互換性上の
  阻害は見当たらない。
- `pnpm audit --prod`: known vulnerability 0。
- 追跡画像は本プロジェクトのfixtureから作成したUI screenshotで、外部素材を含まない。

## Cost and abuse exposure

- core verificationはlocal-onlyでhosted dependency、paid API、cloud resourceを要求しない。
- deployment設定、Cloudflare/hosting manifest、課金API integrationはない。
- remote captureは利用者が明示したHTTP(S)取得のみ。redirect、size、private-address制限を持ち、
  観測結果を自動でEvidenceへ昇格しない。
- Review Workspaceはread-onlyのloopback listenerで、public deployを前提にしていない。

## Documentation readiness

- package metadataはNode.js engineを宣言し、READMEはinstall/check、offline self-test、
  主要CLI workflow、trust boundary、resource limits、Review Workspace screenshotを備える。
- `docs/OPERATOR.md` にproduction-oriented runbook、`docs/TRUST-AUDIT.md` に残る責任境界、
  `docs/PERFORMANCE.md` に公開上限の再現可能な性能試験がある。
- packageは現在 `private: true`。npm公開は意図せず実行できない。
- public deploy手順は、hosted productではないため対象外。

## Commands executed

```text
git log --all -G <token-pattern> --format=%H -- .
git log --all -G <secret-keyword-pattern> -i --format=%H -- .
git grep -IlE <token-pattern> -- .
git ls-files .env* *.pem *.key *.sqlite* *.db HANDOFF.md *.tgz *.zip
pnpm licenses list --prod --json
pnpm audit --prod
pnpm audit:secrets
pnpm benchmark:max-lineage
```

Scanコマンドはsecret本文をterminalへ表示せず、commit/file件数と対象名だけを確認した。

## Integrated private readiness

Repository全体の再確認には次を使う。

```text
pnpm readiness:private
```

このcommandはfull check、live production dependency audit、Gitleaks、offline installed self-test、
packed-install smoke、3-sample maximum-lineage benchmark、同一runtime baselineとの相対性能gateを
順に実行し、production SBOMを生成して公式CycloneDX CLIで検証する。成功時は各gate、
依存/binary/上限/SBOM inventory、baseline/candidate benchmark heads、SBOM head、performance
ratios、JCS receipt headだけを含むpath-free receiptを返す。dependency registryへのnetwork
accessは明示し、public releaseやtrusted timestampを主張しない。

保持したreceiptは、dependency registry、Gitleaks、benchmark、package smokeを再実行せず、外部に
保持したheadを使って軽量検証できる。

```text
pnpm readiness:verify -- \
  --receipt private-readiness.json \
  --expected-sha256 RECEIPT_SHA256
```

この検証はreceiptのclosed shape、全true checks、inventory、performance ratio上限、SBOM validator、
assurance、JCS headを再計算するが、元の各gateを再実行したとは主張しない。

Full readinessの失敗は `repositoryCheck`、`productionDependencyAudit`、`dedicatedSecretAudit`、
`offlineInstalledSelfTest`、`packedInstallSmoke`、`maximumLineageBenchmark`、
`relativePerformanceGate`、`productionSbomValidation`、`packageMetadata`、`receipt` のいずれかを
closed errorの`step`として返す。下位toolのpathや生のerror本文はsummaryへ転送しない。
