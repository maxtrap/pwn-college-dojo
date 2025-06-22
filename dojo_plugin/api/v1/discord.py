"""
Module for interactions between pwn.college's Discord application (called Sensai) and the pwn.college api.
"""

import hmac
from datetime import datetime, date

from flask import request
from flask_restx import Namespace, Resource
from CTFd.models import db
from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user
from typing import Optional, Dict, Any

from ...config import DISCORD_CLIENT_SECRET
from ...models import DiscordUsers, DiscordUserActivity
from ...utils.dojo import get_current_dojo_challenge

import logging

logger = logging.getLogger(__name__)


discord_namespace = Namespace("discord", description="Endpoint to manage discord")

def auth_check(authorization: str):
    """
    FIXME Ensure that the authorization matches Sensai's discord token

    Args:
        authorization: The request's authorization header
    """
    if not authorization or not authorization.startswith("Bearer "):
        return {"success": False, "error": "Unauthorized"}, 401

    token = authorization.split(" ")[1]
    if not hmac.compare_digest(token, DISCORD_CLIENT_SECRET):
        return {"success": False, "error": "Unauthorized"}, 401

    return None, None

@discord_namespace.route("")
class Discord(Resource):
    """
    Represents the /discord endpoint. Only supports DELETE method.
    """
    @authed_only
    def delete(self):
        """
        Disconnects the discord account associated with the logged in user.
        
        In essence, it deletes the discord information of the currently logged in discord user from the database.
        """
        logger.info('A discord delete request has been made. UPDATED CODE HERE')
        user = get_current_user()
        discord_user = DiscordUsers.query.filter_by(user=user).first()
        logger.info(f'{discord_user=}')
        if discord_user: 
            db.session.delete(discord_user)
            db.session.commit()
        return {"success": True} # TODO It seems like it is returning successfully no matter if the discord user was found or not.


@discord_namespace.route("/activity/<discord_id>")
class DiscordActivity(Resource):
    def get(self, discord_id: int):
        """
        Gives information about the challenge which the user with the given discord_id is currently working on 

        Args:
            discord_id: The discord id of the user in question
        """
        authorization = request.headers.get("Authorization")
        res, code = auth_check(authorization)
        if res:
            return res, code

        discord_user = DiscordUsers.query.filter_by(discord_id=discord_id).first()
        if not discord_user:
            return {"success": False, "error": "Discord user not found"}, 404

        dojo_challenge = get_current_dojo_challenge(discord_user.user)
        if not dojo_challenge:
            return {"success": True, "activity": None}

        dojo_challenge = dojo_challenge.resolve() # TODO What exactly does this even do?
        activity = {
            "challenge": {
                "dojo": dojo_challenge.dojo.name,
                "module": dojo_challenge.module.name,
                "challenge": dojo_challenge.name,
                "description": dojo_challenge.description,
                "reference_id": dojo_challenge.reference_id,
            }
        }
        return {"success": True, "activity": activity}


def get_user_activity_prop(discord_id: int, activity: str, start: Optional[datetime] = None, end: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Helper method for the number of `activity` that a discord user has in the time frame betweem `start` and `end`

    Args:
        discord_id: The discord user's discord_id
        activity: The type of activity to be counted. Can be "thanks" or "memes". 
        start: The start datetime object. Defaults to None.
        end: The end datetime object. Defaults to None.

    Returns:
        A dictionary with "success": True and `activity`: number of `activity`
    """
    user: DiscordUsers = DiscordUsers.query.filter_by(discord_id=discord_id).first()
    if not user:
        count = 0
    elif activity == "thanks":
        count = (user.thanks(start, end)
                 .group_by(DiscordUserActivity.message_id, DiscordUserActivity.source_user_id) # TODO what is this for?
                 .count())
    elif activity == "memes":
        count = user.memes(start, end).count()
    return {"success": True, activity: count}

def get_user_activity(discord_id: int, activity: str, request):
    """
    Get the number of `activity` that a discord user has based on the time frame specified in the request arguments

    Args:
        discord_id: The discord user's discord_id
        activity: The type of activity to be counted. Can be "thanks" or "memes".
        request: Flask's request object

    Returns:
        An invalid time format message if the time format is invalid, otherwise it returns the result of `get_user_activity_prop()`.
    """
    authorization = request.headers.get("Authorization")
    res, code = auth_check(authorization)
    if res:
        return res, code

    start_stamp = request.args.get("start")
    end_stamp = request.args.get("end")
    start = None
    end = None

    if start_stamp:
        try:
            start = datetime.fromisoformat(start_stamp)
        except:
            return {"success": False, "error": "invalid start format"}, 400
    if end_stamp:
        try:
            end = datetime.fromisoformat(start_stamp)
        except:
            return {"success": False, "error": "invalid end format"}, 400

    user = DiscordUsers.query.filter_by(discord_id=discord_id).first()

    return get_user_activity_prop(discord_id, activity, start, end)

def post_user_activity(discord_id: int, activity: str, request):
    """
    Helper method for storing discord activity into the database.

    Args:
        discord_id: The discord user's discord_id
        activity: The type of activity to be counted. Can be "thanks" or "memes".
        request: Flask's request object

    Returns:
        Error message if the JSON data is invalid or has missing parameters. Otherwise, it returns the number of of `activity`
        that the user with `discord_id` has after being updated.
    """
    authorization = request.headers.get("Authorization")
    res, code = auth_check(authorization)
    if res:
        return res, code

    data = request.get_json()

    expected_vals = ['source_user_id',
                     'guild_id',
                     'channel_id',
                     'message_id',
                     'message_timestamp',
                     ]

    for ev in expected_vals:
        if ev not in data:
            return {"success": False, "error": f"Invalid JSON data - {ev} not found!"}, 400

    kwargs = {
            'user_id' : discord_id,
            'source_user_id': data.get("source_user_id", ""),
            'guild_id': data.get("guild_id"),
            'channel_id': data.get("channel_id"),
            'message_id': data.get("message_id"),
            'timestamp': data.get("timestamp"),
            'message_timestamp': datetime.fromisoformat(data.get("message_timestamp")),
            'type': activity
            }
    entry = DiscordUserActivity(**kwargs)
    db.session.add(entry)
    db.session.commit()

    return get_user_activity_prop(discord_id, activity), 200

@discord_namespace.route("/memes/user/<discord_id>", methods=["GET", "POST"])
class DiscordMemes(Resource):
    """
    API endpoint for getting and posting meme information
    """
    def get(self, discord_id):
        return get_user_activity(discord_id, "memes", request)

    def post(self, discord_id):
        return post_user_activity(discord_id, "memes", request)

@discord_namespace.route("/thanks/user/<discord_id>", methods=["GET", "POST"])
class DiscordThanks(Resource):
    """
    API endpoint for getting and posting thanks information
    """
    def get(self, discord_id):
        return get_user_activity(discord_id, "thanks", request)

    def post(self, discord_id):
        return post_user_activity(discord_id, "thanks", request)


@discord_namespace.route("/thanks/leaderboard", methods=["GET"])
class GetDiscordLeaderBoard(Resource):
    """
    API endpoint for getting the thanks leaderboard
    """
    def get(self):
        try:
            start = datetime.fromisoformat(request.args.get("start", f"{date.today().year}-01-01"))
        except ValueError:
            return {"success": False, "error": "Invalid start format"}, 400

        score = db.func.count(db.distinct(db.func.concat(DiscordUserActivity.message_id, "-", DiscordUserActivity.source_user_id))).label("score")
        leaderboard_query = (
            db.session.query(DiscordUserActivity.user_id, score)
            .filter(DiscordUserActivity.type == "thanks", DiscordUserActivity.message_timestamp >= start)
            .group_by(DiscordUserActivity.user_id)
            .order_by(score.desc())
            .limit(20)
        )
        leaderboard = [dict(discord_id=discord_id, score=score) for discord_id, score in leaderboard_query]

        return {"success": True, "leaderboard": leaderboard}, 200
