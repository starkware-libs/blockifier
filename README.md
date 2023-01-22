<div align="center">
  <h1>Blockifier</h1>
  <br />
  <a href="https://github.com/starkware-libs/blockifier-old/issues/new?assignees=&labels=bug&template=01_BUG_REPORT.md&title=bug%3A+">Report a Bug</a>
  ·
  <a href="https://github.com/starkware-libs/blockifier-old/issues/new?assignees=&labels=enhancement&template=02_FEATURE_REQUEST.md&title=feat%3A+">Request a Feature</a>
  ·
  <a href="https://github.com/starkware-libs/blockifier-old/discussions/new?category=q-a">Ask a Question</a>
</div>

<div align="center">
<br />

[![GitHub Workflow Status](https://github.com/starkware-libs/blockifier-old/actions/workflows/post-merge.yml/badge.svg)](https://github.com/starkware-libs/blockifier-old/actions/workflows/post-merge.yml)
![License](https://img.shields.io/github/license/starkware-libs/blockifier-old.svg?style=flat-square)(LICENSE)

</div>

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
- [Roadmap](#roadmap)
- [Support](#support)
- [Security](#security)
- [License](#license)

</details>

---

## About

Blockifier is a Rust implementation for the transaction-executing component in the StarkNet sequencer, in charge of creating state diffs and blocks.

## Roadmap
The Blockifier will be a step towards a decentralized sequencer client for StarkNet, allowing anyone to run one.
We'll add more milestones to this table once we finish the first one, where we blockify transactions sequentially, including all existing functionality.

| name                   | status |
|------------------------|:--------:|
| Add the ability to execute a block and output a state diff.                                                                                       | ⏳ |
| Integrate with the existing StarkNet Sequencer by replacing its current transaction-blockifying component, which is written in Python.            |    |
| Implement optimistic concurrency of transaction execution.                                                                                        |    |
| Extend the Blockifier into a full StarkNet sequencer, written in Rust, replacing the one currently in use.                                        |    |

## Support

Reach out to the maintainer at one of the following places:

- [GitHub Discussions](https://github.com/starkware-libs/blockifier-old/discussions)
- Contact options listed on [this GitHub profile](https://github.com/starkware-libs)

## Security

Blockifier follows good practices of security, but 100% security cannot be assured.
Blockifier is provided **"as is"** without any **warranty**. Use at your own risk.

_For more information and to report security issues, please refer to our [security documentation](docs/SECURITY.md)._

## License

This project is licensed under the **Apache 2.0 license**.

See [LICENSE](LICENSE) for more information.
