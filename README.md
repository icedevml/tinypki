# TinyPKI

Convenience wrapper for [Step CA](https://smallstep.com/docs/step-ca/) to facilitate the usage of mTLS for small businesses and home labs, with significantly
minimized hassle.

**Features:**
* Live index of all X.509 Certificates issued by Step CA;
* Detailed view for each X.509 Certificate with the ability to revoke it via GUI;
* Invitations - generate a one-time code that other person/device could redeem for a certificate using a simple
  in-browser key generation and certificate collection process;

All features are available both via Web GUI and JSON API.

**Compatible with:**
* Step CA v0.29.0 (25-12-03); Step CLI v0.29.0 (25-12-03)

## Documentation

* [Demo Guide](docs/demo-guide.md) - a minimal guide if you want to quickly setup the project to try it on;
* [Setup Guide](docs/setup-guide.md) - the full setup guide;
* [Migrating existing Step CA](docs/migration.md) - migrating existing Step CA instance to be indexed by TinyPKI;
* [Security Guide](docs/security-guidelines.md) - security-critical information;
* [Local Development](docs/local-development.md) - tips for setting up local development;
