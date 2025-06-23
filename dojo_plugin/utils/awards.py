import datetime

from CTFd.cache import cache
from CTFd.models import db, Users
from flask import url_for

from .discord import get_discord_roles, get_discord_member, add_role, send_message
from ..models import Dojos, Belts, Emojis, DiscordUsers


BELT_ORDER = [ "orange", "yellow", "green", "purple", "blue", "brown", "red", "black" ]
BELT_REQUIREMENTS = {
    "orange": "intro-to-cybersecurity",
    "yellow": "program-security",
    "green": "system-security",
    "blue": "software-exploitation",
}

def get_user_emojis(user):
    """
    Return the list of all emojis that a user has earned or should earn based on all completed dojos
    """
    emojis = [ ]
    for dojo in Dojos.query.all():
        emoji = dojo.award and dojo.award.get('emoji', None)
        if not emoji:
            continue
        if dojo.challenges and dojo.completed(user):
            emojis.append((emoji, dojo.name, dojo.hex_dojo_id))
    return emojis

def get_belts():
    """
    Returns a dictionary containing belt information.

    The structure is like this (the numbers 42, 39, etc represent user ids):

    {
        dates: {
            orange: {
                42: 1970-01-01T00:00:00Z,
                ...
            }
            yellow: {
                39: 1970-01-01T00:00:00Z,
                ...
            }
        }
        users: {
            42: {
                handle: herobrine,
                site: example.com,
                color: blue,
                date: 1970-01-01T00:00:00Z 
            }
            ...
        }
        ranks: {
            orange: [42, 39, ...],
            yellow: [39, 2, ...]
        }
    }
    """
    result = dict(dates={}, users={}, ranks={})
    for color in reversed(BELT_ORDER):
        result["dates"][color] = {}
        result["ranks"][color] = []

    belts = (
        Belts.query
        .join(Users)
        .filter(Belts.name.in_(BELT_ORDER), ~Users.hidden)
        .with_entities(
            Belts.date,
            Belts.name.label("color"),
            Users.id.label("user_id"),
            Users.name.label("handle"),
            Users.website.label("site"),
        )
    ).all()
    belts.sort(key=lambda belt: (-BELT_ORDER.index(belt.color), belt.date))

    for belt in belts:
        result["dates"][belt.color][belt.user_id] = str(belt.date)
        if belt.user_id not in result["users"]:
            result["users"][belt.user_id] = dict(
                handle=belt.handle,
                site=belt.site,
                color=belt.color,
                date=str(belt.date)
            )
            result["ranks"][belt.color].append(belt.user_id)

    return result

def get_viewable_emojis(user):
    """
    Returns dictionary containing all awards that are viewable to a user.

    If a different user hides their profile or finishes a private dojo, those awards are not viewable to the given user and thus are not included.
    The dictionary maps each user to a list of all of the awards they recieved.
    Within the list, each award has information about the award description, emoji, count (always set to 1), and dojo url corresponding to the award
    """
    result = { }
    viewable_dojo_urls = {
        dojo.hex_dojo_id: url_for("pwncollege_dojo.listing", dojo=dojo.reference_id)
        for dojo in Dojos.viewable(user=user).where(Dojos.data["type"] != "example")
    }
    emojis = (
        Emojis.query
        .join(Users)
        .filter(~Users.hidden, db.or_(Emojis.category.in_(viewable_dojo_urls.keys()), Emojis.category == None))
        .order_by(Emojis.date)
        .with_entities(
            Emojis.name,
            Emojis.description,
            Emojis.category,
            Users.id.label("user_id"),
        )
    )
    for emoji in emojis:
        result.setdefault(emoji.user_id, []).append({
            "text": emoji.description,
            "emoji": emoji.name,
            "count": 1,
            "url": viewable_dojo_urls.get(emoji.category, "#"),
        })
    return result

def update_awards(user):
    """
    Updates the user's belt and emoji awards

    This function:
        - Checks all of the belt requirements to see if the user has the requirements but is missing their belt, and grants the appropriate belt if it is missing
        - It also updates the belt roles on discord
        - Checks all of the user's emojis and grants emojis if they were earned and are missing
    """
    current_belts = [belt.name for belt in Belts.query.filter_by(user=user)] # Get all the belts that the user has already earned 
    for belt, dojo_id in BELT_REQUIREMENTS.items():
        if belt in current_belts: # If they already earned the belt, no need to check for a new belt.
            continue
        dojo = Dojos.query.filter(Dojos.official, Dojos.id == dojo_id).first()
        if not (dojo and dojo.completed(user)):
            break # Break if any of the dojos are unsolved. This is key to ensure if a later dojo is solved, they don't earn the belt until they solve the earlier dojos
        db.session.add(Belts(user=user, name=belt))
        db.session.commit()
        current_belts.append(belt)

    discord_user = DiscordUsers.query.filter_by(user=user).first()
    discord_member = discord_user and get_discord_member(discord_user.discord_id)
    discord_roles = get_discord_roles()
    for belt in BELT_REQUIREMENTS:
        if belt not in current_belts:
            continue
        belt_role = belt.title() + " Belt"
        missing_role = discord_member and discord_roles.get(belt_role) not in discord_member["roles"]
        if not missing_role:
            continue
        add_role(discord_user.discord_id, belt_role)
        send_message(f"<@{discord_user.discord_id}> earned their {belt_role}! :tada:", "belting-ceremony")
        cache.delete_memoized(get_discord_member, discord_user.discord_id)

    current_emojis = get_user_emojis(user)
    for emoji, dojo_name, dojo_id in current_emojis:
        # note: the category filter is critical, since SQL seems to be unable to query by emoji!
        emoji_award = Emojis.query.filter_by(user=user, name=emoji, category=dojo_id).first()
        if emoji_award:
            continue
        db.session.add(Emojis(user=user, name=emoji, description=f"Awarded for completing the {dojo_name} dojo.", category=dojo_id))
        db.session.commit()
