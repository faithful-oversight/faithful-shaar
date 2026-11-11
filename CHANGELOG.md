# Changelog

All notable changes to this project are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project foundation: license, documentation, contribution and security policies, continuous integration, and release pipeline.

### Changed

- The license check reads optional extras and platform-specific dependencies correctly, matching merilo and toledot. It no longer replaces a license a package states with a generic classifier, and reviewed exceptions are pinned to a package version.

### Fixed

- The source archive now includes `scripts`, which its tests import, and the build check collects the tests from an extracted copy.
