# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added:
 - a lot of rustdoc comments, and some general comments
 - tests for hex encoding of keys

### Fixed:
 - hex encoding of the keys was broken, works now

### Changed:
 - restructured the source code, split it up into multiple files

## [v0.1.0] - 2020-04-16
Initial release. This doesn't do much yet, and the docs are lacking. It can:
 - generate keys
 - parse keys from yggdrasil-go
 - generate addresses for those keys
