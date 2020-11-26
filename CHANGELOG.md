# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog], and this project adheres to
[Semantic Versioning]. The file is auto-generated using [Conventional Commits].

[keep a changelog]: https://keepachangelog.com/en/1.0.0/
[semantic versioning]: https://semver.org/spec/v2.0.0.html
[conventional commits]: https://www.conventionalcommits.org/en/v1.0.0/

## Overview


- [`0.1.0`](#010) – _2020-11-26_

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
    "chore": "Maintenance Work",
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
