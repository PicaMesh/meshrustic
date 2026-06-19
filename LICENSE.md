# Licensing

MeshRustic is **dual-licensed**:

| License | Who it fits | Document |
|---------|-------------|----------|
| **GNU AGPL v3** | Hobbyists, researchers, and anyone who can comply with AGPL copyleft (source availability when you distribute or offer the software to users) | [LICENSE](LICENSE) |
| **Commercial** | Businesses, integrators, service providers, and public-sector deployments that need proprietary terms without AGPL obligations | [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) |

Choose **one** license that applies to your use. They are alternatives, not cumulative.

## Quick guide

**Use AGPL (free)** if you are fine with:

- Providing source to recipients when you distribute binaries or devices containing modified MeshRustic
- AGPL network-use requirements if you run modified versions as a service users interact with over a network

**Buy a commercial license** if you need to ship closed firmware, avoid source disclosure to end customers, or your contract/procurement rules do not allow AGPL.

## Third-party software

Rust dependencies and bundled tools retain their own licenses. See [NOTICE](NOTICE).
Run `cargo license` in the dev container before release builds.

## Provenance

MeshRustic source in this repository is original PicaMesh work. Wire-format
compatibility with other LoRa mesh nodes is by public specification only; no
Meshtastic firmware source is incorporated.
