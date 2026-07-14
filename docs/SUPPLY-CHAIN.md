# Supply-chain inventory

Evidence Forgeのproduction dependency inventoryは、repository checkoutで次のように生成します。

```bash
pnpm sbom:production > evidence-forge.cdx.json
```

出力はCycloneDX JSON 1.6のapplication SBOMです。`pnpm list --prod` の到達可能な依存graphと
`pnpm licenses list --prod` のlicense evidenceを突き合わせ、production componentだけを含めます。
現在のgraphはrootから `parse5@8.0.1`、さらに `entities@8.0.0` へ到達する2 componentです。

再現性とprivacyのため、timestamp、random serial、ローカルpath、registry URL、author、homepageは
含めません。componentとdependency edgeをPackage URL順にsortし、`pnpm-lock.yaml` 全bytesの
SHA-256をmetadata propertyへ保持します。依存componentのlicenseが1件でも解決できない場合は
不完全なSBOMを出力せずfail closedします。

公式CycloneDX CLIによるschema validationは次で実行します。

```bash
pnpm sbom:validate
```

validatorがない、installed treeと`package.json`の直接依存が一致しない、license evidenceが競合する、
またはCycloneDX JSON 1.6 validationに失敗する場合は成功summaryを出しません。2026-07-14時点では
Homebrew coreの `cyclonedx-cli 0.32.0` で2 components / 3 dependency relationshipsを検証済みです。

このSBOMは依存構成のinventoryであり、脆弱性がないこと、artifactが署名済みであること、取得時刻が
信頼されることを単独では証明しません。脆弱性確認は `pnpm audit --prod`、repository全体のgateは
`pnpm readiness:private` を使用します。
