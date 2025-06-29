import datetime
import hashlib
import hmac
import io
import logging
import os
import pytz
import re
import tarfile
import tempfile

import bleach
import docker
import docker.errors
from flask import current_app, Response, Markup, abort, g
from itsdangerous.url_safe import URLSafeSerializer
from CTFd.exceptions import UserNotFoundException, UserTokenExpiredException
from CTFd.models import db, Solves, Challenges, Users
from CTFd.utils.encoding import hexencode
from CTFd.utils.user import get_current_user
from CTFd.utils.modes import get_model
from CTFd.utils.config.pages import build_markdown
from CTFd.utils.security.sanitize import sanitize_html
from sqlalchemy import String, Integer
from sqlalchemy.sql import or_
from typing import Optional, Union
from docker import DockerClient
from pathlib import Path


from ..config import WORKSPACE_NODES
from ..models import Dojos, DojoMembers, DojoAdmins, DojoChallenges, WorkspaceTokens
from .mac_docker import MacDockerClient

ID_REGEX = "^[A-Za-z0-9_.-]+$"
def id_regex(s):
    return re.match(ID_REGEX, s) and ".." not in s


def force_cache_updates():
    return bool(os.environ.get("CACHE_WARMER"))


def container_name(user):
    return f"user_{user.id}"


def container_password(container, *args):
    """
    Joins all of the args, and returns a sha256 of the args along with the container auth_token (random 32-bit value generated during container startup) 
    """
    key = container.labels["dojo.auth_token"].encode()
    message = "-".join(args).encode()
    return hmac.HMAC(key, message, "sha256").hexdigest()


def get_current_container(user=None):
    """
    Returns the currently running challenge container of the provided user, or the currently logged in user if user=None. Otherwise, None.
    """
    user = user or get_current_user()
    if not user:
        return None

    docker_client = user_docker_client(user)

    try:
        return docker_client.containers.get(container_name(user))
    except docker.errors.NotFound:
        return None


def get_all_containers(dojo=None): # I think this should be renamed to get_all_challenge_containers() - Max
    """
    Get all the challenge containers that users are currently working in.

    If dojo is None, it returns all containers from all dojos on the platform.
    If dojo is specified, it returns all containers for that dojo.
    """
    filters = dict(status="running", label="dojo.dojo_id")
    if dojo:
        filters["label"] = f"dojo.dojo_id={dojo.reference_id}"

    return [
        container
        for docker_client in all_docker_clients()
        for container in docker_client.containers.list(filters=filters, ignore_removed=True)
    ]


def serialize_user_flag(account_id, challenge_id, *, secret=None):
    """
    Serializes the user flag based on the account_id and challenge_id using that app secret.
    
    Then it reverses the resulting data as a layer of obfuscation. Oops, you know too much.
    Optionally, a secret key can be passed in to be used instead of the configured app secret key.
    """
    if secret is None:
        secret = current_app.config["SECRET_KEY"]
    serializer = URLSafeSerializer(secret)
    data = [account_id, challenge_id]
    user_flag = serializer.dumps(data)[::-1]
    return user_flag


def unserialize_user_flag(user_flag, *, secret=None):
    """
    Reverse of the `serialize_user_flag` operation and returns the account_id and challenge_id based on the provided flag
    """
    if secret is None:
        secret = current_app.config["SECRET_KEY"]
    user_flag = re.sub(".+?{(.+)}", r"\1", user_flag)[::-1]
    serializer = URLSafeSerializer(secret)
    account_id, challenge_id = serializer.loads(user_flag)
    return account_id, challenge_id


def user_node(user):
    """
    Returns the node id of the workspace node associated with the given user. Returns None if the dojo is in single node configuration.

    The node associated with the user is calculated by doing user.id % num of workspace nodes, which means that users
    are roughly evenly distributed among the nodes.
    """
    return list(WORKSPACE_NODES.keys())[user.id % len(WORKSPACE_NODES)] if WORKSPACE_NODES else None


def user_docker_client(user: Users, image_name: Optional[str] = None) -> Union[DockerClient, MacDockerClient]:
    """
    Retrieves the docker client for communicating with the `user`'s docker image

    FIXME If the dojo is configured in a multi-node arrangement, this function will return the docker client
    associated with the docker container node within the {FIXME} to which the `user` belongs to. Each user is pseudo-randomly
    assigned a node based on their user id.

    If the dojo is configured in a single-node arrangment, it will simply return the main FIXME docker container client.

    Args:
        user: The user whose docker client to retrieve
        image_name: FIXME The image name associated with the user, if it is known.
        This is only checked if the server is being run on a Mac machine. Defaults to None.

    Returns:
        The docker client object.
    """
    if image_name and image_name.startswith("mac:"):
        return MacDockerClient()

    node_id = user_node(user)
    return (docker.DockerClient(base_url=f"tcp://192.168.42.{node_id + 1}:2375", tls=False)
            if node_id is not None else docker.from_env())


def all_docker_clients():
    """
    Returns all docker clients that are configured for running the dojo.
    
    If the dojo is multi-node, it returns docker clients for all nodes.
    Otherwise, it just returns a singleton list with the docker client for the main node.
    """
    return [docker.DockerClient(base_url=f"tcp://192.168.42.{node_id + 1}:2375", tls=False)
            for node_id in WORKSPACE_NODES] if WORKSPACE_NODES else [docker.from_env()]


def user_ipv4(user: Users) -> str:
    """
    Generates an ipv4 address for the user on the subnet 10.0.0.0/8

    The full ip address bits are layed out as follows:
              NODE       SERVICE_ID
    00001010  0000  00000000000000000000

    Four bits are for the NODE_ID, and is determined from `user_node`.
    20 bits are for SERVICE_ID, and is determined as user.id + 256.
    SERVICE_IDs 0-255 are reserved for core services
    """

    node_id = user_node(user) or 0
    service_id = user.id + 256
    assert node_id < 2**4
    assert service_id < 2**20
    return ".".join([
        "10",
        f"{(node_id << 4) | ((service_id >> 16) & 0xff)}",
        f"{(service_id >> 8) & 0xff}",
        f"{(service_id >> 0) & 0xff}",
    ])


def redirect_internal(redirect_uri, auth=None):
    """
    Triggers an nginx redirect to the specified uri
    """
    response = Response()
    if auth:
        response.headers["X-Accel-Redirect"] = "@forward"
        response.headers["redirect_auth"] = auth
    else:
        response.headers["X-Accel-Redirect"] = "/internal/"
    response.headers["redirect_uri"] = redirect_uri
    return response


def redirect_user_socket(user, port, url_path):
    """
    Triggers an internal redirect to the proper service based on the user, port and path
    """
    assert user is not None
    return redirect_internal(f"http://{user_ipv4(user)}:{port}/{url_path}")


def render_markdown(s):
    """
    Safely returns html from a markup string. If an official dojo is being loaded, it does not clean the html.
    """
    raw_html = build_markdown(s or "")
    if "dojo" in g and (g.dojo.official or g.dojo.privileged):
        return Markup(raw_html) # Official dojos are assumed to be safe 

    markdown_tags = [
        "h1", "h2", "h3", "h4", "h5", "h6",
        "b", "i", "strong", "em", "tt",
        "p", "br",
        "span", "div", "blockquote", "code", "pre", "hr",
        "ul", "ol", "li", "dd", "dt",
        "img",
        "a",
        "sub", "sup",
    ]
    markdown_attrs = {
        "*": ["id"],
        "img": ["src", "alt", "title"],
        "a": ["href", "alt", "title"],
        "p": ["data-hide"]
    }
    clean_html = bleach.clean(raw_html, tags=markdown_tags, attributes=markdown_attrs)
    return Markup(clean_html)


def resolved_tar(dir: Path, *, root_dir: Path, filter=None) -> io.BytesIO:
    """
    Packs a directory into an in-memory tar archive, resolving and validating symlinks to ensure they don’t point outside a trusted root directory.

    Args:
        dir: The directory to pack into an archive
        root_dir: The security boundary. The function ensures symlinks don't point outside this directory.
        filter: Optional filter function used to only keep files that match a specific criteria. Must take Path object as an argument. Defaults to None.
    """
    tar_buffer = io.BytesIO()
    tar = tarfile.open(fileobj=tar_buffer, mode='w')
    resolved_root_dir = root_dir.resolve()
    for path in dir.rglob("*"):
        if filter is not None and not filter(path):
            continue
        relative_path = path.relative_to(dir)
        if path.is_symlink():
            resolved_path = path.resolve()
            assert resolved_path.is_relative_to(resolved_root_dir), f"The symlink {path} points outside of the root directory"
            tar.add(resolved_path, arcname=relative_path)
        else:
            tar.add(path, arcname=relative_path, recursive=False)
    tar_buffer.seek(0)
    return tar_buffer


def is_dojo_admin(user: Users, dojo: Dojos) -> bool:
    """
    Returns True if the `user` is an admin of the `dojo`, False otherwise
    """
    return user and dojo and dojo.is_admin(user)


def user_dojos(user):
    filters = [Dojos.official == True]
    if user:
        members = db.session.query(DojoMembers.dojo_id).filter(DojoMembers.user_id == user.id)
        filters.append(Dojos.id.in_(members.subquery()))
        admins = db.session.query(DojoAdmins.dojo_id).filter(DojoAdmins.user_id == user.id)
        filters.append(Dojos.id.in_(admins.subquery()))
    return Dojos.query.filter(or_(*filters)).all()


def dojo_standings(dojo_id=None, fields=None, module_id=None):
    if fields is None:
        fields = []

    Model = get_model()

    dojo_filters = []
    if dojo_id is None:
        dojos = Dojos.query.filter_by(official=True).all()
        dojo_filters.append(or_(*(dojo.challenges_query(module_id=module_id) for dojo in dojos)))
    else:
        dojo = Dojos.query.filter(Dojos.id == dojo_id).first()
        dojo_filters.append(dojo.challenges_query(module_id=module_id))

        if not dojo.public:
            members = db.session.query(DojoMembers.user_id).filter_by(dojo_id=dojo_id)
            dojo_filters.append(Solves.account_id.in_(members.subquery()))

    standings_query = (
        db.session.query(*fields)
        .join(Challenges)
        .join(Model, Model.id == Solves.account_id)
        .filter(Challenges.value != 0, Model.banned == False, Model.hidden == False,
                *dojo_filters)
    )

    return standings_query


def load_dojo(dojo_id, dojo_spec, user=None, dojo_dir=None, commit=True, log=logging.getLogger(__name__), initial_join_code=None):
    log.info("Initiating dojo load.")

    dojo = Dojos.query.filter_by(id=dojo_id).first()
    if not dojo:
        dojo = Dojos(id=dojo_id, owner_id=None if not user else user.id, data=dojo_spec)
        dojo.join_code = initial_join_code
        log.info("Dojo is new, adding.")
        db.session.add(dojo)
    elif dojo.data == dojo_spec:
        # make sure the previous load was fully successful (e.g., all the imports worked and weren't fixed since then)
        num_loaded_chals = DojoChallenges.query.filter_by(dojo_id=dojo_id).count()
        num_spec_chals = sum(len(module.get("challenges", [])) for module in dojo.config.get("modules", []))

        if num_loaded_chals == num_spec_chals:
            log.warning("Dojo is unchanged, aborting update.")
            return
    else:
        dojo.data = dojo_spec
        db.session.add(dojo)

    if dojo.config.get("dojo_spec", None) != "v2":
        log.warning("Incorrect dojo spec version (dojo_spec attribute). Should be 'v2'")

    dojo.apply_spec(dojo_log=log, dojo_dir=dojo_dir)

    if commit:
        log.info("Committing database changes!")
        db.session.commit()
    else:
        log.info("Rolling back database changes!")
        db.session.rollback()


def first_bloods():
    first_blood_string = db.func.min(Solves.date.cast(String)+"|"+Solves.user_id.cast(String))
    first_blood_query = (
        db.session.query(Challenges.id.label("challenge_id"))
        .join(Solves, Challenges.id == Solves.challenge_id)
        .add_columns(
            db.func.substring_index(first_blood_string, "|", -1).cast(Integer).label("user_id"),
            db.func.min(Solves.date).label("timestamp")
        )
        .group_by(Challenges.id)
        .order_by("timestamp")
    ).all()
    return first_blood_query


def daily_solve_counts():
    counts = (
        db.session.query(
            Solves.user_id, db.func.count(Solves.challenge_id).label("solves"),
            db.func.year(Solves.date).label("year"),
            db.func.month(Solves.date).label("month"),
            db.func.day(Solves.date).label("day")
        )
        .join(Challenges, Challenges.id == Solves.challenge_id)
        .filter(~Challenges.category.contains("embryo"))
        .group_by("year", "month", "day", Solves.user_id)
    ).all()
    return counts


# https://github.com/CTFd/CTFd/blob/3.6.0/CTFd/utils/security/auth.py#L51-L59
def lookup_workspace_token(token):
    token = WorkspaceTokens.query.filter_by(value=token).first()
    if token:
        if datetime.datetime.utcnow() >= token.expiration:
            raise UserTokenExpiredException
        return token.user
    else:
        raise UserNotFoundException
    return None


# https://github.com/CTFd/CTFd/blob/3.6.0/CTFd/utils/security/auth.py#L37-L48
def generate_workspace_token(user, expiration=None):
    temp_token = True
    while temp_token is not None:
        value = "workspace_" + hexencode(os.urandom(32))
        temp_token = WorkspaceTokens.query.filter_by(value=value).first()

    token = WorkspaceTokens(
        user_id=user.id, expiration=expiration, value=value
    )
    db.session.add(token)
    db.session.commit()
    return token

def is_challenge_locked(dojo_challenge: DojoChallenges, user: Users) -> bool:
    if all((dojo_challenge.progression_locked, dojo_challenge.challenge_index != 0, not dojo_challenge.dojo.is_admin())):
        previous_dojo_challenge = dojo_challenge.module.challenges[dojo_challenge.challenge_index - 1]
        return not (Solves.query.filter_by(user=user, challenge=dojo_challenge.challenge).first() or
                Solves.query.filter_by(user=user, challenge=previous_dojo_challenge.challenge).first())
    return False
    


# based on https://stackoverflow.com/questions/36408496/python-logging-handler-to-append-to-list
class ListHandler(logging.Handler): # Inherit from logging.Handler
    def __init__(self, log_list):
        logging.Handler.__init__(self)
        self.log_list = log_list

    def emit(self, record):
        self.log_list.append(record.levelname + ": " + record.getMessage())

class HTMLHandler(logging.Handler): # Inherit from logging.Handler
    def __init__(self, start_tag="<code>", end_tag="</code>", join_tag="<br>"):
        logging.Handler.__init__(self)
        self.html = ""
        self.start_tag = start_tag
        self.end_tag = end_tag
        self.join_tag = join_tag

    def reset(self):
        self.html = ""

    def emit(self, record):
        if self.html:
            self.html += self.join_tag
        self.html += f"{self.start_tag}<b>{record.levelname}</b>: {sanitize_html(record.getMessage())}{self.end_tag}"

