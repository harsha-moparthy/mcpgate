from __future__ import annotations

import secrets
import time
from typing import Any

import jwt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    OAuthClientInformationFull,
    OAuthToken,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from pydantic import AnyUrl

from .config import Settings
from .policy import Policy
from .store import Store


class OAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """OAuth 2.1 authorization-code provider with PKCE and token rotation.

    Clients are statically provisioned by policy for this deployable demo. The
    official MCP SDK validates client authentication and PKCE around this provider.
    Codes and refresh tokens are single-use and persisted in SQLite.
    """

    def __init__(self, store: Store, policy: Policy, settings: Settings):
        self.store = store
        self.policy = policy
        self.settings = settings

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        client = self.policy.client(client_id)
        if client is None:
            return None
        return OAuthClientInformationFull(
            client_id=client.client_id,
            client_secret=client.secret,
            client_name=client.client_id,
            redirect_uris=[AnyUrl("http://127.0.0.1/callback")],
            token_endpoint_auth_method="client_secret_post",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=" ".join(sorted(client.scopes)),
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise NotImplementedError(
            "dynamic registration is disabled; provision clients in policy.yaml"
        )

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        scopes = params.scopes or (client.scope or "").split()
        try:
            scopes = self.policy.authorize_scopes(str(client.client_id), scopes)
        except PermissionError as exc:
            raise AuthorizeError("invalid_scope", str(exc)) from exc
        if params.resource and params.resource != self.settings.resource_url:
            raise AuthorizeError("invalid_request", "resource indicator does not match this server")
        code = secrets.token_urlsafe(32)
        expires_at = time.time() + 120
        payload = {
            "scopes": scopes,
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "resource": params.resource or self.settings.resource_url,
        }
        self.store.put_artifact(
            code, "authorization_code", str(client.client_id), payload, expires_at
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        payload = self.store.get_artifact(authorization_code, "authorization_code")
        if payload is None or payload["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=payload["scopes"],
            expires_at=payload["expires_at"],
            client_id=payload["client_id"],
            code_challenge=payload["code_challenge"],
            redirect_uri=AnyUrl(payload["redirect_uri"]),
            redirect_uri_provided_explicitly=payload["redirect_uri_provided_explicitly"],
            resource=payload["resource"],
            subject=payload["client_id"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        payload = self.store.get_artifact(
            authorization_code.code, "authorization_code", consume=True
        )
        if payload is None or payload["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "authorization code expired, invalid, or replayed")
        return self._issue_pair(payload["client_id"], payload["scopes"], payload["resource"])

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        payload = self.store.get_artifact(refresh_token, "refresh_token")
        if payload is None or payload["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=payload["client_id"],
            scopes=payload["scopes"],
            expires_at=int(payload["expires_at"]),
            subject=payload["client_id"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        payload = self.store.get_artifact(refresh_token.token, "refresh_token", consume=True)
        if payload is None or payload["client_id"] != client.client_id:
            raise TokenError("invalid_grant", "refresh token expired, invalid, or replayed")
        requested = scopes or payload["scopes"]
        if not set(requested) <= set(payload["scopes"]):
            raise TokenError("invalid_scope", "refresh cannot increase scopes")
        try:
            requested = self.policy.authorize_scopes(payload["client_id"], requested)
        except PermissionError as exc:
            raise TokenError("invalid_scope", str(exc)) from exc
        return self._issue_pair(payload["client_id"], requested, self.settings.resource_url)

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(
                token,
                self.settings.jwt_secret,
                algorithms=["HS256"],
                audience=self.settings.resource_url,
                issuer=self.settings.issuer_url,
                options={"require": ["exp", "iat", "jti", "sub", "aud", "iss"]},
            )
        except jwt.PyJWTError:
            return None
        artifact = self.store.get_artifact(token, "access_token")
        if artifact is None or artifact.get("jti") != claims["jti"]:
            return None
        return AccessToken(
            token=token,
            client_id=claims["client_id"],
            scopes=list(claims["scopes"]),
            expires_at=int(claims["exp"]),
            resource=self.settings.resource_url,
            subject=claims["sub"],
            claims=claims,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.store.revoke_artifact(token.token)

    def issue_for_client(
        self, client_id: str, secret: str, scopes: list[str] | None = None
    ) -> OAuthToken:
        """Local bootstrap helper; validates client credentials before issuing.

        Production clients use the SDK's authorization-code + PKCE endpoints. This
        helper keeps tests and CLI demos deterministic without bypassing policy.
        """
        client = self.policy.client(client_id)
        if client is None or not secrets.compare_digest(client.secret, secret):
            raise PermissionError("invalid_client")
        requested = self.policy.authorize_scopes(client_id, scopes or sorted(client.scopes))
        return self._issue_pair(client_id, requested, self.settings.resource_url)

    def _issue_pair(self, client_id: str, scopes: list[str], resource: str) -> OAuthToken:
        client = self.policy.client(client_id)
        if client is None:
            raise TokenError("invalid_client", "unknown client")
        now = int(time.time())
        jti = secrets.token_urlsafe(18)
        claims: dict[str, Any] = {
            "iss": self.settings.issuer_url,
            "aud": resource,
            "sub": client_id,
            "client_id": client_id,
            "scopes": scopes,
            "teams": sorted(client.teams),
            "iat": now,
            "exp": now + self.settings.access_token_ttl,
            "jti": jti,
        }
        access_token = jwt.encode(claims, self.settings.jwt_secret, algorithm="HS256")
        self.store.put_artifact(
            access_token,
            "access_token",
            client_id,
            {"jti": jti, "scopes": scopes},
            claims["exp"],
        )
        refresh_token = secrets.token_urlsafe(36)
        self.store.put_artifact(
            refresh_token,
            "refresh_token",
            client_id,
            {"scopes": scopes},
            now + self.settings.refresh_token_ttl,
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=self.settings.access_token_ttl,
            scope=" ".join(scopes),
            refresh_token=refresh_token,
        )
