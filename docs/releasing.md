[← Documentation](../README.md#documentation) · Previous: [Development](development.md)

# Releasing

Releases are built by GitHub Actions ([.github/workflows/release.yml](../.github/workflows/release.yml)) when a version tag is pushed.

1. **Write the release notes** in `docs/releases/vX.Y.Z.md` (see [v0.1.0](releases/v0.1.0.md)):
   - Open with a sentence or two on what the release brings.
   - Then the changes, grouped under `##` headings, with **bold** leads.
   - End with anything users must do when upgrading.

   Don't add a downloads section: the workflow adds it.
2. **Try the release build locally** (optional). This builds every archive into `dist/`, the same way the workflow does:

   ```bash
   VERSION=X.Y.Z scripts/release.sh
   ```
3. **Tag and push:**

   ```bash
   git tag -a vX.Y.Z -m "grepalert X.Y.Z"
   git push origin main vX.Y.Z
   ```

The workflow then:
- **Tests:** builds the web UI, then runs `go vet` and the tests.
- **Binaries:** builds `grepalert-agent` and `grepalert-dashboard` for Linux, macOS and Windows (amd64/arm64), with the version set to `X.Y.Z`. They're packed with the README, the release notes (`RELEASE_NOTES.md`), the license and example configs, plus `checksums.txt`.
- **GitHub Release:** publishes release `vX.Y.Z`. Its text is:
  1. `docs/releases/vX.Y.Z.md`
  2. a **Downloads** section with the `docker pull` commands
  3. GitHub's generated list of changes

  The archives are attached. A tag with a hyphen, like `v0.2.0-rc.1`, becomes a pre-release. Pushing the tag again (after moving it) updates the existing release.
- **Images:** builds and pushes `ghcr.io/<owner>/grepalert-agent` and `ghcr.io/<owner>/grepalert-dashboard` for linux/amd64 and linux/arm64, tagged `X.Y.Z`, `X.Y` and `latest`. Pre-releases don't get `latest`.

**First release only:** GitHub creates the two container packages as **private**. On GitHub, open your profile → **Packages** → each `grepalert-*` package → **Package settings**, set the visibility to **Public**, and link it to the repository. Only then can anyone pull the images.

When the release is published, the workflow also rebuilds the [documentation site](https://fadhaw.github.io/grepalert/), so its release notes page shows the new version.

The [CI workflow](../.github/workflows/ci.yml) runs on every push to `main` and on pull requests:
- builds the UI
- runs `gofmt`, `go vet` and the tests
- runs `govulncheck`
- builds both images for both architectures
