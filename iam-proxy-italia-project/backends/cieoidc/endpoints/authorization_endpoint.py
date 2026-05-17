import logging
import inspect
import json
import time
import uuid

from datetime import datetime, timezone
from pydantic import ValidationError
from types import SimpleNamespace
from typing import Callable, Optional, List
from copy import deepcopy

from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from satosa.response import Redirect
from ..models.oidc_auth import OidcAuthentication
from ..models.trust_chain_cache import TrustChainCache
from ..utils import KeyUsage
from ..utils.exceptions import TrustChainNotFoundError
from ..utils.handlers.base_endpoint import BaseEndpoint
from ..utils.helpers.jwtse import create_jws
from ..utils.helpers.jwks import public_jwk_from_private_jwk
from ..utils.helpers.misc import (
    random_string,
    get_pkce,
    get_key,
    http_dict_to_redirect_uri_path
)
from ..storage.db_engine import OidcDbEngine
from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.federation.statements import EntityStatement, get_entity_configurations
from backends.cieoidc.cieoidc import CieOidcBackend

logger = logging.getLogger(__name__)


def _trust_chain_from_cache(cached: TrustChainCache):
    """
    Build a minimal trust-chain-like object from TrustChainCache.
    Has .subject and .subject_configuration.payload as required by authorization endpoint.
    """
    wrapper = SimpleNamespace()
    wrapper.subject = cached.provider_url
    wrapper.subject_configuration = SimpleNamespace(payload=cached.payload)
    return wrapper


def _is_cache_expired(cached: TrustChainCache, now=None) -> bool:
    """Return True if the cached payload is expired (exp in the past)."""
    exp = cached.exp or cached.payload.get("exp")
    if exp is None:
        return False
    t = now if now is not None else time.time()
    return t >= exp


class TrustChainResolver:
    """
    Resolves trust chains from cache or builds them on-demand via discovery.
    When a provider is requested but not in the cache (e.g. startup failed),
    discovery is performed and the resulting trust chain is stored for reuse.
    """

    def __init__(self, trust_chains: dict, build_callback):
        """
        :param trust_chains: Dict of provider_url -> TrustChainBuilder (mutated when new chains are built)
        :param build_callback: Callable(provider_url) -> TrustChainBuilder; raises TrustChainNotFoundError on failure
        """
        self._chains = trust_chains
        self._build = build_callback

    def __contains__(self, key):
        return key in self._chains

    def __getitem__(self, key):
        return self._chains[key]

    def keys(self):
        return self._chains.keys()

    def get_or_build(self, provider_url: str) -> TrustChainBuilder:
        """Get trust chain from cache, or discover and store it on-demand."""
        for key in (
            provider_url,
            provider_url.rstrip("/"),
            provider_url + "/" if not provider_url.endswith("/") else None,
        ):
            if key and key in self._chains:
                return self._chains[key]
        return self._build(provider_url)


class AuthorizationHandler(BaseEndpoint):
    def __init__(
        self,
        config: dict,
        internal_attributes: dict[str, dict[str, str | list[str]]],
        base_url: str,
        name: str,
        auth_callback_func: Callable[[Context, InternalData], Response],
        converter: AttributeMapper,
    ) -> None:
        """
        Não recebe trustchain pois passou a ser construída em tempo de execução.
        """
        logger.debug(
            f"Initializing: {self.__class__.__name__}."
        )
        super().__init__(config, internal_attributes, base_url, name, auth_callback_func, converter)
        self._entity_type = self.config.get("entity_type")
        self._jwks_core = self.config.get("jwks_core")
        self._validated_trust_anchors: List[EntityStatement] = []
        self.providers = self.config.get("providers", [])
        self.trust_chain = self._generate_trust_chains()
        self._trust_chain_resolver = TrustChainResolver(
            self.trust_chain,
            self.get_or_build_trust_chain,
        )

    @property
    def _jwks(self) -> dict:
        _dic_jwks: dict[str, dict] = {self._entity_type: {}}
        _dic_jwks[self._entity_type]["jwks"] = [public_jwk_from_private_jwk(_k) for _k in self._jwks_core]
        return _dic_jwks

    def _require_config_field(self, path, label):
        value = self.config
        try:
            for key in path:
                value = value[key]
        except (KeyError, TypeError):
            raise ValueError(f"{label} is missing in {self.__class__.__name__}")
        if not value:
            raise ValueError(f"{label} is empty in {self.__class__.__name__}")
        return value

    def _validate_configs(self):
        """
        Validates essential configuration fields for the authorization endpoint.
        """
        self._require_config_field(
            ["endpoints", "authorization_endpoint"], "Authorization endpoint")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config"], "Authorization endpoint config")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config", "metadata"], "Metadata")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config", "metadata", "openid_relying_party"],
            "OpenId Relying Party")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config", "metadata", "openid_relying_party", "client_id"],
            "Client ID")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config", "metadata",
             "openid_relying_party", "redirect_uris"],
            "Redirect URI")

    def endpoint(self, context, *args):
        """
        Handles the authentication response from the OP.
        :type context: satosa.context.Context
        :type args: Any
        :rtype: satosa.response.Response

        :param context: SATOSA context
        :param args: None
        :return:
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [context {context}]"
        )

        provider_url = context.internal_data.get("target_entity_id")
        if not provider_url:
            return self._handle_400(
                context,
                "No identity provider was selected. The request is missing target_entity_id.",
            )

        # adiciona o provider para manter compatibilidade mesmo em multitenant e ser possivel fazer verificações
        self.providers.append(provider_url)

        try:
            trust_chain = self.__get_trust_chain(provider_url)
        except TrustChainNotFoundError as exc:
            logger.warning(
                "Trust chain not found for provider %s: %s",
                provider_url,
                exc,
                exc_info=False,
            )
            return self._handle_500(
                context,
                "The selected identity provider is temporarily unavailable. "
                "Please try again later or choose another provider.",
                exc,
            )

        metadata = trust_chain.subject_configuration.payload["metadata"]["openid_provider"]
        authorization_endpoint = metadata["authorization_endpoint"]

        # generate the authorization dict
        authz_data = self.__authorization_data(authorization_endpoint, context)

        # Add key prompt
        # Caso prompt esteja presente na requisição, adiciona ao authz, necessário para permitir dinamicidade na request
        if context.qs_params.get("prompt"):
            authz_data["prompt"] = context.qs_params.get("prompt")

        # Add key idp_hint
        if context.qs_params.get("idp_hint"):
            authz_data["idp_hint"] = context.qs_params.get("idp_hint")

        # generation pkce value
        self.__pkce_generation(authz_data)

        authorization_entity = dict(
            client_id=self.config["metadata"]["openid_relying_party"]["client_id"],
            state=authz_data["state"],
            endpoint=authorization_endpoint,
            provider_id=trust_chain.subject,
            data=json.dumps(authz_data),
            provider_configuration=trust_chain.subject_configuration.payload["metadata"]
        )

        self.__insert(authorization_entity, context)

        self.__create_jws(authz_data)

        uri_path = AuthorizationHandler.generate_uri(authz_data)

        if "?" in authorization_endpoint:
            qstring = "&"
        else:
            qstring = "?"
        url = qstring.join((authorization_endpoint, uri_path))

        resp = Redirect(url)

        return resp

    def __get_trust_chain(self, provider: str) -> TrustChainBuilder:
        """
        Get trust chain from cache or via on-demand discovery.
        When the trust chain is not in cache, a TrustChainResolver (if present)
        will discover and build it, then store it for reuse.
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}."
            f"Params[provider: {provider}]"
        )
        # Try cache first (dict lookup with URL normalization)
        for key in (provider, provider.rstrip("/"), provider + "/" if not provider.endswith("/") else None):
            if key and key in self._trust_chain_resolver:
                return self._trust_chain_resolver[key]

        # On-demand discovery: resolver builds and stores the chain
        if hasattr(self._trust_chain_resolver, "get_or_build"):
            return self._trust_chain_resolver.get_or_build(provider)

        configured = list(self._trust_chain_resolver.keys()) if hasattr(self._trust_chain_resolver, "keys") else []
        if not configured:
            raise TrustChainNotFoundError(
                "The selected identity provider could not be used: no trust chains "
                "are available. This usually means trust chain generation failed during "
                "startup—for example, the trust anchor or CIE provider was unreachable. "
                "Please check the server logs at startup for details, and ensure the "
                "trust anchor and provider services are healthy."
            ) from None
        raise TrustChainNotFoundError(
            f"The identity provider '{provider}' is not available. "
            f"Available providers: {', '.join(configured)}. "
            "If you expected this provider to be available, trust chain generation "
            "may have failed for it at startup. Check the server logs for "
            "'Exception ... generated from this provider' messages."
        ) from None

    def __authorization_data(self, provider_authorization_endpoint: str, context) -> dict:
        """
        method private authorization_data:
        This method generate the authorization data for the authorization endpoint.

        :type self: object
        :rtype: dict

        :param self: object
        :return: dict
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}.]"
        )

        _timestamp_now = int(datetime.now(timezone.utc).timestamp())
        # local do campo scope alterado para ser válido, fora da entity configuration

        # Resgatamos do scope e acr_values da request em context, para permitir dinamicidade na request
        scope = context.qs_params.get("scope")
        acr_values = context.qs_params.get("acr_values") or []

        claim = self.config["metadata"]["openid_relying_party"]["claim"]

        response_type: str = self.config["metadata"]["openid_relying_party"]["response_types"][0]

        try:
            authz_data = dict(
                iss=self.config["metadata"]["openid_relying_party"]["client_id"],
                scope=scope,
                redirect_uri=self.config["metadata"]["openid_relying_party"]["redirect_uris"][0],
                response_type=response_type,
                nonce=random_string(32),
                state=random_string(32),
                client_id=self.config["metadata"]["openid_relying_party"]["client_id"],
                endpoint=provider_authorization_endpoint,
                acr_values=acr_values,
                # TODO Ask this to Giuseppe because into Django this variable is empty or not? OIDCFED_ACR_PROFILES = getattr(settings,"OIDCFED_ACR_PROFILES",AcrValues.l2.value)
                iat=_timestamp_now,
                exp=_timestamp_now + 60,
                jti=str(uuid.uuid4()),
                aud=provider_authorization_endpoint,
                claims=claim,
            )
        except Exception as exception:
            logger.error("Exception where generate the authz_data: {}".format(exception))
            raise exception

        return authz_data

    def __pkce_generation(self, authz_data: dict):
        """
        method private pkce_generation:
        Get method and length from configuration and generate, with utils module, the pkce values.
        Add this value into authorization data and return the dictionary updated
        :type self: object
        :type authz_data: dict

        :param self: object
        :param authz_data: dict
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [authz_data {authz_data}]"
        )
        if not self.config["metadata"]["openid_relying_party"]["code_challenge"]["length"]:
            raise ValueError("code_challenge length in configuration is empty")

        if not self.config["metadata"]["openid_relying_party"]["code_challenge"]["method"]:
            raise ValueError("code_challenge method in configuration is empty")

        rp_meta = self.config["metadata"]["openid_relying_party"]["code_challenge"]
        code_challenge_length: int = rp_meta["length"]
        code_challenge_method: str = rp_meta["method"]

        pkce_values = get_pkce(code_challenge_method, code_challenge_length)

        authz_data.update(pkce_values)

    def __create_jws(self, authz_data: dict):
        """
        method private __create_jws:
        This method get key and generate the JWS.
        Add the object into authorization data and return the dictionary updated

        :type self: object
        :type authz_data: dict

        :param self: object
        :param authz_data: dict
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [authz_data {authz_data}]"
        )

        authz_data_obj = deepcopy(authz_data)

        authz_data_obj["iss"] = self.config["metadata"]["openid_relying_party"][
            "client_id"
        ]

        jwk_core_sig = get_key(self._jwks_core, KeyUsage.signature)

        request_obj = create_jws(authz_data_obj, jwk_core_sig)

        authz_data["request"] = request_obj

    @staticmethod
    def generate_uri(authz_data: dict) -> str:
        """
        method __generate_uri:
        This method generate the URI from authorization data.

        :type self: object
        :type authz_data: dict
        :rtype: dict

        :param self: object
        :param authz_data: dict
        :return: dict
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [authz_data {authz_data}]"
        )

        request_uri_object = {
            "client_id": authz_data["client_id"],
            "scope": authz_data["scope"],
            "response_type": authz_data["response_type"],
            "code_challenge": authz_data["code_challenge"],
            "code_challenge_method": authz_data["code_challenge_method"],
            "request": authz_data["request"]
        }

        if "prompt" in authz_data:
            request_uri_object["prompt"] = authz_data["prompt"]

        if "idp_hint" in authz_data:
            request_uri_object["idp_hint"] = authz_data["idp_hint"]

        uri_path = http_dict_to_redirect_uri_path(request_uri_object)

        return uri_path

    def __insert(self, obj: dict, context):
        """
        method __insert:
        This method insert the input dictionary into DB layer.

        :type self: object
        :type input: dict

        :param self: object
        :param input: dict

        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [input {obj}]"
        )

        try:
            auth = OidcAuthentication(**obj)
            self.__prepare_for_insert(auth)
            auth.id = str(uuid.uuid4())

            auth_dump = auth.model_dump(mode="json")

            # Salva no context (recebido como parâmetro)
            # Substituímos a implementação o mongo db
            # colocando as informações no context do satosa
            if context:
                context.state["satosa_authz_state"] = auth_dump
            else:
                logger.warning("Context não disponível para salvar auth")

            logger.info(f"Objeto de autenticação criado (stateless) com sucesso")

        except ValidationError as e:
            logger.error(f"Erro de validação: {e}")
        except Exception as e:
            logger.error(f"Erro inesperado: {e}")

    def __prepare_for_insert(self, auth_entity: OidcAuthentication):
        """Prepara a entidade para inserção"""
        now = datetime.now(timezone.utc)
        if auth_entity.created is None:
            auth_entity.created = now
        auth_entity.modified = now

    # Esse metódo foi movido da classe principal CieOidcBackend pois é necessário para um contexto
    # multitenant que a trust chain seja criada em tempo de execução, além de não ser utilizada nos demais handlers.
    def _generate_trust_chains(self) -> dict:
        """try load from DB, or can try discovery with TA's list."""
        httpc_params = self.config["trust_chain"]["config"]["httpc_params"]
        trust_chains = dict()

        for provider_url in self.providers:
            # try load from DB
            engine = self._get_storage()
            if engine:
                cached = engine.get_trust_chain_by_provider(provider_url)
                if cached and not _is_cache_expired(cached):
                    chain = _trust_chain_from_cache(cached)
                    self._add_to_dict(trust_chains, provider_url, chain)
                    continue

            # Build via discovery, tryng each TA
            try:
                tas = self._ensure_trust_anchors()
                chain_built = False
                for ta_ec in tas:
                    try:
                        chain = CieOidcBackend.generate_trust_chain(
                            ta_ec, provider_url, httpc_params
                        )
                        self._add_to_dict(trust_chains, provider_url, chain)
                        self._store_trust_chain(chain, provider_url)
                        logger.info(
                            "Provider %s linked to TA %s", provider_url, ta_ec.sub
                        )
                        chain_built = True
                        break
                    except Exception as e:
                        logger.warning(
                            "Failed to build trust chain for provider %s with TA %s: %s",
                            provider_url,
                            getattr(ta_ec, "sub", "<unknown>"),
                            e,
                        )
                if not chain_built:
                    logger.error(
                        "Could not build trust chain for provider %s with any configured trust anchor",
                        provider_url,
                    )
            except Exception as e:
                logger.error(
                    "Could not resolve trust chain for %s: %s", provider_url, e
                )

        return trust_chains

    def _store_trust_chain(self, chain, provider_url: str) -> None:
        """Persist trust chain to database if storage is available."""
        engine = self._get_storage()
        if engine is None:
            return
        try:
            payload = chain.subject_configuration.payload
            exp = payload.get("exp")
            variants = {
                provider_url.rstrip("/"),
                provider_url.rstrip("/") + "/"
            }

            for url in variants:
                cached = TrustChainCache(
                    provider_url=url,
                    payload=payload,
                    exp=exp,
                    created=datetime.now(timezone.utc),
                )
                engine.add_or_update_trust_chain(cached)
        except Exception as e:
            logger.warning("Could not persist trust chain for %s: %s", provider_url, e)

    def _get_storage(self) -> Optional[OidcDbEngine]:
        """Create and return storage engine; connect if needed. Returns None if no storage configured."""
        if getattr(self, "_storage_engine", None) is not None:
            return self._storage_engine
        storage_config = self.config.get("storage") or {}
        if not storage_config:
            return None
        try:
            engine = OidcDbEngine(storage_config)
            engine.connect()
            self._storage_engine = engine
            return engine
        except Exception as e:
            logger.warning("Could not initialize storage for trust chain persistence: %s", e)
            return None

    def get_or_build_trust_chain(self, provider_url: str) -> TrustChainBuilder:
        """
        Get trust chain from cache, or from DB, or discover and build it on-demand.
        Newly built chains are stored in memory and in the database.
        """
        provider_variants = [provider_url, provider_url.rstrip("/")]
        if not provider_url.endswith("/"):
            provider_variants.append(provider_url + "/")
        if not any(p in self.providers for p in provider_variants if p):
            raise TrustChainNotFoundError(f"Provider {provider_url} not in allowed list.")

        # Try load from DB (in-memory cache already checked by TrustChainResolver)
        engine = self._get_storage()
        if engine:
            cached = engine.get_trust_chain_by_provider(provider_url)
            if cached and not _is_cache_expired(cached):
                chain = _trust_chain_from_cache(cached)
                self._add_to_dict(self.trust_chain, provider_url, chain)
                return chain

        httpc_params = self.config["trust_chain"]["config"]["httpc_params"]
        tas = self._ensure_trust_anchors()

        for ta_ec in tas:
            try:
                chain = CieOidcBackend.generate_trust_chain(ta_ec, provider_url, httpc_params)
                self._add_to_dict(self.trust_chain, provider_url, chain)
                self._store_trust_chain(chain, provider_url)
                return chain
            except Exception:
                continue

        raise TrustChainNotFoundError(f"Failed to build trust chain for {provider_url} with any TA.")

    def _ensure_trust_anchors(self) -> List[EntityStatement]:
        """Return a list of valid TAs."""
        if not self._validated_trust_anchors:
            httpc_params = self.config["trust_chain"]["config"]["httpc_params"]
            ta_urls = self.config["trust_chain"]["config"]["trust_anchor"]

            for ta_url in ta_urls:
                try:
                    jwt = get_entity_configurations(ta_url, httpc_params=httpc_params)[0]
                    ta_ec = EntityStatement(jwt, httpc_params=httpc_params)
                    ta_ec.validate_by_itself()
                    self._validated_trust_anchors.append(ta_ec)
                except Exception as e:
                    logger.error(f"Failed to validate TA {ta_url}: {e}")

            if not self._validated_trust_anchors:
                raise ValueError("No valid Trust Anchors could be loaded.")

        return self._validated_trust_anchors

    def _add_to_dict(self, d, url, chain):
        """Helper to add a normalized URL in a dict."""
        # Always store the exact URL key.
        d[url] = chain
        # Also store the normalized variant (with/without trailing slash),
        # but avoid silently overwriting an existing normalized entry.
        norm = url.rstrip("/") if url.endswith("/") else url + "/"
        if norm != url:
            if norm in d:
                logger.warning(
                    "Duplicate provider URL variants configured: %s and %s; "
                    "keeping existing trust chain for %s",
                    url,
                    norm,
                    norm,
                )
            else:
                d[norm] = chain
