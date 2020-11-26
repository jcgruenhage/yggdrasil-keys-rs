# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning]. The file is auto-generated using [Conventional Commits].

[keep a changelog]: https://keepachangelog.com/en/1.0.0/
[semantic versioning]: https://semver.org/spec/v2.0.0.html
[conventional commits]: https://www.conventionalcommits.org/en/v1.0.0/

## Overview


- [`0.2.0`](#020) – _2020-11-26_
- [`0.1.0`](#010) – _2020-11-26_

## [0.2.0] – _2020.11.26_

### Contributions

This release is made possible by the following people (in alphabetical order).
Thank you all for your contributions. Your work – no matter how significant – is
greatly appreciated by the community. 💖

- Jan Christian Grünhage (<jan.christian@gruenhage.xyz>)


### Changes

#### Maintenance

- **bump version to 0.2.0 and update changelog** ([`b9b605d`])

- **add crate details to Cargo.toml** ([`2eb8948`])

- **update dependencies** ([`be18f94`])

- **generate changelog with jilu** ([`cc9793b`])

- **reformat code** ([`a5ca6f4`])

- **update dependencies** ([`6a0581a`])

#### Refactoring

- **switch to thiserror** ([`a5832aa`])

- **restructure code and add docs** ([`e2fe454`])

#### Bug Fixes

- **avoid overflow in shifting logic** ([`c51afe1`])

  We previously had a bug which caused on average one eighth of the keys
  to have wrong addresses generated for them. This commit fixes that, adds
  regression tests and makes the methods more generic.

- **extend and fix encryption key tests** ([`fea3f5c`])

  This had failing tests before, which have now been replaced by working
  tests. The broken tests were caused by golang's curve25519 impl doing
  key generation slightly different than curve25519-dalek. In the end,
  both impls end up with the same result when using the keys though, so
  these tests failing is perfectly fine.

- **patch hex encoding of keys** ([`1ed551a`])

  Previously, the hex encoding of the keys was done wrongly, it's been
  fixed by using the hex crate for encoding. This commit also added some
  tests to check for regressions to this.

#### Features

- **use ipnet's Ipv6Net for subnets** ([`d6bd07f`])

## [0.1.0] – _2020.11.26_

Initial release. Supports basic generation of keys, parsing of
yggdrasil-go keys and generation of addresses for those keys.



<!--
Config(
  accept_types: ["feat", "fix", "perf", "chore", "refactor"],
  type_headers: {
    "feat": "Features",
    "fix": "Bug Fixes",
    "perf": "Performance Improvements",
    "chore": "Maintenance",
    "refactor": "Refactoring"
  }
)

Template(
# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning]. The file is auto-generated using [Conventional Commits].

[keep a changelog]: https://keepachangelog.com/en/1.0.0/
[semantic versioning]: https://semver.org/spec/v2.0.0.html
[conventional commits]: https://www.conventionalcommits.org/en/v1.0.0/

## Overview

{% for release in releases %}
- [`{{ release.version }}`](#{{ release.version | replace(from=".", to="") }}) – _{{ release.date | date(format="%Y-%m-%d")}}_
{%- endfor %}

{% for release in releases -%}
## [{{ release.version }}] – _{{ release.date | date(format="%Y.%m.%d") }}_
{%- if release.notes %}

{{ release.notes }}
{% endif -%}
{%- if release.changeset.contributors %}

### Contributions

This release is made possible by the following people (in alphabetical order).
Thank you all for your contributions. Your work – no matter how significant – is
greatly appreciated by the community. 💖
{% for contributor in release.changeset.contributors %}
- {{ contributor.name }} (<{{ contributor.email }}>)
{%- endfor %}
{%- endif %}

{% if release.changeset.changes | length > 0 %}
### Changes

{% for type, changes in release.changeset.changes | group_by(attribute="type") -%}

#### {{ type | typeheader }}

{% for change in changes -%}
- **{{ change.description }}** ([`{{ change.commit.short_id }}`])

{% if change.body -%}
{{ change.body | indent(n=2) }}

{% endif -%}
{%- endfor -%}

{% endfor %}
{%- endif %}
{%- endfor -%}
)
-->
