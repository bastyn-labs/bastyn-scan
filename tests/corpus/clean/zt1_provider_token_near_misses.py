"""Values that look close to a provider token but are not committed secrets."""

import os

# A token read at run time.
DEPLOY_LOGIN = os.environ["DEPLOY_LOGIN"]

# Words and settings that contain "token" but hold no provider token.
MAX_TOKENS = 4096
TOKENIZER_NAME = "whitespace"

# A commit SHA, an image digest and an action pin: hexadecimal, not a token.
COMMIT = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
IMAGE = "registry.example.org/app@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
ACTION_PIN = "actions/checkout@a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"

# The same shape inside a URL, a markdown link target and a file path.
CLONE_URL = "https://ci.example.org/clone/ghp_o9X5Y5Rktgm66QoT6mKaaLNA9gTuSM4PVrKw"
DOCS_LINK = "[how to publish](docs/npm_QIkZ9122pQlWIlfICCBx01kc3NHN0a5PlbVN.md)"
CACHE_FILE = "/var/cache/npm_aucoMLTc63KFAaRbCpubhU9u39wyZolWraR6"

# Placeholders in the exact token shape.
PLACEHOLDER_A = "npm_abcdefghijklmnopqrstuvwxyz0123456789"
PLACEHOLDER_B = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# AWS's published placeholder access key ID.
AWS_DOC_KEY = "AKIAIOSFODNN7EXAMPLE"
