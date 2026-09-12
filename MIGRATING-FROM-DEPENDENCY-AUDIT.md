<!-- Migration guidance from the predecessor plugin without silently widening trust. -->
# Migrating from Dependency Audit

Dependency Audit is now the deprecated predecessor. Supply Chain Guard preserves its registry candidate resolution, archive scanner, approvals, batch review, factory bundle, rollback, install bypass, and security POC behavior, then adds selected cargo-vet `safe-to-run` evidence and bounded review of immutable public GitHub dependencies.

The plugins intentionally use separate executable names, configuration directories, environment variables, and approval files. Existing Dependency Audit approvals are not migrated automatically because changing the product and evidence policy should not silently expand trust.

## Approval files and trusted dependencies

Supply Chain Guard does not read or modify Dependency Audit's approval file. Their default paths are deliberately separate:

| Platform | Dependency Audit | Supply Chain Guard |
| --- | --- | --- |
| Linux/macOS | `$XDG_CONFIG_HOME/cargo-wrapper-dependency-audit/approvals.toml`, or `~/.config/cargo-wrapper-dependency-audit/approvals.toml` | `$XDG_CONFIG_HOME/cargo-wrapper-supply-chain-guard/approvals.toml`, or `~/.config/cargo-wrapper-supply-chain-guard/approvals.toml` |
| Windows | `%APPDATA%\CargoWrapperDependencyAudit\approvals.toml` | `%APPDATA%\CargoWrapperSupplyChainGuard\approvals.toml` |

The two versions remain compatible for Dependency Audit's registry approval records. Each migrated `[[approvals]]` record remains bound to its registry source, crate name, version, checksum, approved finding set, and scanner version. Supply Chain Guard can additionally write `content_sha256` for Git approvals; Dependency Audit does not understand that field. This one-way registry compatibility makes a deliberate migration possible; it does not make the old file a shared live store.

If Dependency Audit's factory bundle was installed, its exact entries were merged into the same `[[approvals]]` array as personal decisions. The `factory_bundles` field records the installed bundle version but does not label each entry's origin, so the old file cannot mechanically separate factory-derived and personal approvals. For a clean migration, install Supply Chain Guard's factory bundle independently and recreate selected personal decisions; for full continuity, explicitly transfer the complete old trust state.

Choose one migration policy:

1. **Fresh review, least inherited trust:** leave the new approval file absent and let Supply Chain Guard review artifacts again. If desired, inspect and install Supply Chain Guard's own factory bundle separately.
2. **Personal approvals only:** create the new file using only the old file's `[[approvals]]` tables that you still intend to trust. Do not copy `[[workspaces]]` cached fingerprints or the `factory_bundles` marker. Missing top-level sections safely default to empty.
3. **Complete explicit trust-state transfer:** copy the old file to the new path only before the new file exists. This also transfers cached workspace fingerprints and factory-bundle state, so use it only when you deliberately want the new plugin to inherit all previous trust decisions.

Never configure both plugins to use the same file through their environment-variable overrides. Their schemas happen to be compatible now, but sharing a mutable store couples two independently versioned security tools and makes later schema or scanner changes unsafe.

1. Disable Dependency Audit:

   ```sh
   cargo wrapper plugin disable dependency-audit
   ```

2. Install Supply Chain Guard and inspect its status/sources.
3. Enable it:

   ```sh
   cargo wrapper plugin enable supply-chain-guard
   ```

4. Select one approval migration policy above. The recommended default is a fresh review; copying selected `[[approvals]]` tables is appropriate when preserving reviewed exact identities is more practical.

Do not enable both guards. Supply Chain Guard detects both names in the captured protocol chain and rejects before candidate resolution, with a command to disable one.
