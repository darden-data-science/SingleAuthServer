"""SingleAuthServer version info.

This is the SINGLE source of truth for the version. pyproject.toml reads it via
`[tool.setuptools.dynamic]`, and build-image.sh reads it to tag the image — so
bumping the tuple below is the only edit a release needs.
"""

# Copyright (c) Michael Albert.
# Distributed under the terms of the Modified BSD License.

version_info = (
    0,
    2,
    0,
    'dev0',  # comment-out this line for a release
)
__version__ = '.'.join(map(str, version_info[:3]))

if len(version_info) > 3:
    __version__ = '%s.%s' % (__version__, version_info[3])
