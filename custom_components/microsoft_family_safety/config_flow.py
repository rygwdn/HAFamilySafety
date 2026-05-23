"""Config flow for Microsoft Family Safety integration."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import unquote

from pyfamilysafety.authenticator import Authenticator
from pyfamilysafety.exceptions import HttpException
import voluptuous as vol

from homeassistant import config_entries
import homeassistant.helpers.config_validation as cv
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError

from .const import (
    AVAILABLE_PLATFORMS,
    CONF_AUTH_URL,
    CONF_CONTROLS,
    CONF_PLATFORMS,
    CONF_REDIRECT_URL,
    CONF_REFRESH_TOKEN,
    CONF_UPDATE_INTERVAL,
    DEFAULT_CONTROLS,
    DEFAULT_PLATFORMS,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    ERROR_AUTH_FAILED,
    INTEGRATION_NAME,
    MS_AUTH_PARAMS,
    MS_LOGIN_URL,
)

_LOGGER = logging.getLogger(__name__)


def _build_auth_url() -> str:
    """Build the Microsoft authentication URL."""
    params = "&".join([f"{k}={v}" for k, v in MS_AUTH_PARAMS.items()])
    return f"{MS_LOGIN_URL}?{params}"


async def validate_redirect_url(hass: HomeAssistant, redirect_url: str) -> dict[str, Any]:
    """Validate the redirect URL by attempting to authenticate."""
    try:
        redirect_url = unquote(redirect_url)
        authenticator = await Authenticator.create(
            token=redirect_url,
            use_refresh_token=False,
        )
        _LOGGER.debug(
            "Authentication success, expiry time %s", authenticator.expires
        )
        return {
            "title": INTEGRATION_NAME,
            "refresh_token": authenticator.refresh_token,
        }
    except HttpException as err:
        _LOGGER.error("HTTP error during authentication: %s", err)
        raise InvalidAuth from err
    except Exception as err:
        _LOGGER.error("Unexpected error during authentication: %s", err)
        raise InvalidAuth(f"Cannot connect: {err}") from err


class FamilySafetyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Microsoft Family Safety."""

    VERSION = 1

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> FamilySafetyOptionsFlow:
        """Get the options flow for this handler."""
        return FamilySafetyOptionsFlow(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Single-step setup: show sign-in link then collect the redirect URL."""
        from .auth.addon_client import AddonCookieClient

        errors: dict[str, str] = {}

        if user_input is not None:
            redirect_url = user_input.get(CONF_REDIRECT_URL, "").strip()
            update_interval = user_input.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL)
            platforms = user_input.get(CONF_PLATFORMS, DEFAULT_PLATFORMS)
            auth_url = user_input.get(CONF_AUTH_URL, "").strip() or None

            if not redirect_url:
                errors[CONF_REDIRECT_URL] = "no_redirect_url"
            else:
                try:
                    info = await validate_redirect_url(self.hass, redirect_url)
                    refresh_token = info["refresh_token"]
                    await self.async_set_unique_id(refresh_token[:20])
                    self._abort_if_unique_id_configured()

                    # Auto-detect addon URL if the user didn't supply one
                    if auth_url is None:
                        addon_client = AddonCookieClient(self.hass)
                        _, detected_url = await addon_client.detect_auth_source()
                        auth_url = detected_url

                    data: dict[str, Any] = {CONF_REFRESH_TOKEN: refresh_token}
                    if auth_url:
                        data[CONF_AUTH_URL] = auth_url

                    return self.async_create_entry(
                        title=info["title"],
                        data=data,
                        options={
                            CONF_UPDATE_INTERVAL: update_interval,
                            CONF_PLATFORMS: platforms,
                        },
                    )
                except InvalidAuth:
                    errors["base"] = ERROR_AUTH_FAILED
                except Exception:
                    _LOGGER.exception("Unexpected exception during authentication")
                    errors["base"] = "unknown"

        # Detect addon to decide whether to show the auth_url field
        addon_client = AddonCookieClient(self.hass)
        source_type, _ = await addon_client.detect_auth_source()

        schema_fields: dict[Any, Any] = {
            vol.Required(CONF_REDIRECT_URL): str,
            vol.Optional(CONF_UPDATE_INTERVAL, default=DEFAULT_UPDATE_INTERVAL): vol.All(
                vol.Coerce(int), vol.Range(min=30, max=3600)
            ),
            vol.Optional(CONF_PLATFORMS, default=DEFAULT_PLATFORMS): cv.multi_select(
                {p: p for p in AVAILABLE_PLATFORMS}
            ),
        }
        if source_type == "none":
            schema_fields[vol.Optional(CONF_AUTH_URL, default="")] = str

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(schema_fields),
            description_placeholders={"auth_url": _build_auth_url()},
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> FlowResult:
        """Handle reauth if token expires."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Re-authenticate with a fresh redirect URL."""
        errors: dict[str, str] = {}

        if user_input is not None:
            redirect_url = user_input.get(CONF_REDIRECT_URL, "").strip()

            if not redirect_url:
                errors[CONF_REDIRECT_URL] = "no_redirect_url"
            else:
                try:
                    info = await validate_redirect_url(self.hass, redirect_url)
                    entry = self.hass.config_entries.async_get_entry(
                        self.context["entry_id"]
                    )
                    if entry:
                        new_data: dict[str, Any] = {
                            CONF_REFRESH_TOKEN: info["refresh_token"]
                        }
                        if CONF_AUTH_URL in entry.data:
                            new_data[CONF_AUTH_URL] = entry.data[CONF_AUTH_URL]

                        self.hass.config_entries.async_update_entry(entry, data=new_data)
                        await self.hass.config_entries.async_reload(entry.entry_id)
                        return self.async_abort(reason="reauth_successful")
                except InvalidAuth:
                    errors["base"] = ERROR_AUTH_FAILED
                except Exception:
                    _LOGGER.exception("Unexpected exception during reauth")
                    errors["base"] = "unknown"

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_REDIRECT_URL): str}),
            description_placeholders={"auth_url": _build_auth_url()},
            errors=errors,
        )


class FamilySafetyOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for Microsoft Family Safety."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_UPDATE_INTERVAL,
                        default=self._config_entry.options.get(
                            CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=30, max=3600)),
                    vol.Optional(
                        CONF_PLATFORMS,
                        default=self._config_entry.options.get(
                            CONF_PLATFORMS, DEFAULT_PLATFORMS
                        ),
                    ): cv.multi_select({p: p for p in AVAILABLE_PLATFORMS}),
                    vol.Optional(
                        CONF_AUTH_URL,
                        default=self._config_entry.data.get(CONF_AUTH_URL, ""),
                    ): str,
                    vol.Optional(
                        CONF_CONTROLS,
                        default=self._config_entry.options.get(
                            CONF_CONTROLS, DEFAULT_CONTROLS
                        ),
                    ): bool,
                }
            ),
        )


class InvalidAuth(HomeAssistantError):
    """Error to indicate authentication failure."""
