import time

import requests
from flask import url_for
from CTFd.cache import cache

from ..models import DiscordUsers
from ..config import DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_BOT_TOKEN, DISCORD_GUILD_ID


OAUTH_ENDPOINT = "https://discord.com/api/oauth2"
API_ENDPOINT = "https://discord.com/api/v9"


def discord_request(endpoint, method="GET", **kwargs):
    """
    Performs a discord API request to the provided endpoint

    Default method is GET. Returns the response based on the appropriate response
    """
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    while True:
        response = requests.request(method, f"{API_ENDPOINT}{endpoint}", headers=headers, **kwargs)
        if response.status_code == 429:
            retry_after = response.json().get("retry_after", 1)
            time.sleep(retry_after)
            continue
        break
    response.raise_for_status()
    if "application/json" in response.headers.get("Content-Type", ""):
        return response.json()
    else:
        return response.content


def guild_request(endpoint, method="GET", **kwargs):
    """
    Returns the result of a discord API request to the provided discord guild (aka server) endpoint. 
    """
    return discord_request(f"/guilds/{DISCORD_GUILD_ID}{endpoint}", method=method, **kwargs)


def get_bot_join_server_url():
    # "Server Members Intent" also required
    params = dict(client_id=DISCORD_CLIENT_ID, scope="bot", permissions=268437504, guild_id=DISCORD_GUILD_ID)
    url = requests.Request("GET", f"{OAUTH_ENDPOINT}/authorize", params=params).prepare().url
    return url


def discord_avatar_asset(discord_member):
    if not discord_member:
        return url_for("views.themes", path="img/dojo/discord_logo.svg")
    discord_id = discord_member["user"]["id"]
    discord_avatar = discord_member["user"]["avatar"]
    return f"https://cdn.discordapp.com/avatars/{discord_id}/{discord_avatar}.png"


def get_discord_id(auth_code):
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": url_for("discord.discord_redirect", _external=True),
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    response = requests.post(f"{OAUTH_ENDPOINT}/token", data=data, headers=headers)
    access_token = response.json()["access_token"]

    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    response = requests.get(f"{API_ENDPOINT}/users/@me", headers=headers)
    discord_id = response.json()["id"]
    return discord_id


@cache.memoize(timeout=3600)
def get_discord_member(discord_id):
    """
    Retrieves the discord member object from the discord API
    """
    if not DISCORD_BOT_TOKEN or not discord_id:
        return
    try:
        result = guild_request(f"/members/{discord_id}")
    except requests.exceptions.RequestException:
        return None
    if result.get("message") == "Unknown Member":
        return None
    return result


@cache.memoize(timeout=3600)
def get_discord_roles():
    """
    Gets all of the discord roles that are in the guild
    """
    if not DISCORD_BOT_TOKEN:
        return {}
    roles = guild_request("/roles")
    return {role["name"]: role["id"] for role in roles}


def send_message(message, channel_name):
    """
    Sends a discord message in the provided channel_name. Exactly 1 channel of the provided name must exist on the server, otherwise an error is thrown.
    """
    channel_ids = [channel["id"] for channel in guild_request("/channels") if channel["name"] == channel_name]
    assert len(channel_ids) == 1, f"There must be exactly 1 channel named {channel_name} on the server"
    channel_id = channel_ids[0]
    json = dict(content=message)
    discord_request(f"/channels/{channel_id}/messages", method="POST", json=json)


def add_role(discord_id, role_name):
    """
    Adds the role with the provided role_name to the discord user with the provided discord_id
    """
    role_id = get_discord_roles()[role_name]
    guild_request(f"/members/{discord_id}/roles/{role_id}", method="PUT")
