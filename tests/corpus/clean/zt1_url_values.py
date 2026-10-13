"""Credential-shaped names holding public endpoint URLs: nothing here is a secret."""

TOKEN_URI = "https://oauth2.provider.invalid/token"
info = {}
info["token_uri"] = "https://oauth2.provider.invalid/token"
config = {"secret_manager_url": "https://secrets.provider.invalid/v1/resolve"}
