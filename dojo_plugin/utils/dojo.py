"""
Handles everything to do with dojo creation.
"""
import os
import re
import subprocess
import sys
import tempfile
import functools
import inspect
import pathlib
import urllib.request

import yaml
import requests
import typing
from typing import Any, Union
from schema import Schema, Optional, Regex, Or, Use, SchemaError
from flask import abort, g
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from pathlib import Path
from CTFd.models import db, Challenges, Flags
from CTFd.utils.user import get_current_user, is_admin

from ..models import DojoAdmins, Dojos, DojoModules, DojoChallenges, DojoResources, DojoChallengeVisibilities, DojoResourceVisibilities, DojoModuleVisibilities, Users
from ..config import DOJOS_DIR
from ..utils import get_current_container
from .dojo_creation.dojo_builder import dojo_from_spec


DOJOS_TMP_DIR = DOJOS_DIR/"tmp"
DOJOS_TMP_DIR.mkdir(exist_ok=True)



def setdefault_name(data):
    """
    Sets the "name" key in the given `data` dictionary based on the "id" key.

    Does nothing any of the following:
        - "import" or "name" is already present in the `data`
        - "id" is not present in the `data`

    Otherwise, sets "name" to the "id" value with hyphens replaced by spaces and title-cased.
    """
    if "import" in data:
        return
    if "name" in data:
        return
    if "id" not in data:
        return
    data["name"] = data["id"].replace("-", " ").title()


def setdefault_description(data, file_path):
    """
    Sets the "description" key of the `data` dictionary to the contents of the file with the given `file_path`.

    It only does this if the `file_path` exists and if the description hasn't already been specified in the yaml.
    """
    if file_path.exists():
        data.setdefault("description", file_path.read_text())


def setdefault_subyaml(data: dict[str, Any], subyaml_path: Path):
    """
    Loads in the subyaml and inserts anything defined in the subyaml into data that isn't already defined in data.
    
    Overwrites fields of subyaml with the top-level data. This means that anything defined in the top-level yaml takes precendence.
    """
    if not subyaml_path.exists():
        return data

    topyaml_data = dict(data)
    subyaml_data = yaml.safe_load(subyaml_path.read_text())
    data.clear()
    data.update(subyaml_data)
    data.update(topyaml_data) # This overwrites any subyaml data with the "topyaml" data


def load_dojo_subyamls(data: dict[str, Any], dojo_dir: Path) -> dict[str, Any]:
    """
    The dojo yaml gets augmented with additional yamls and markdown files found in the dojo repo structure.

    The meta-structure is:

    repo-root/dojo.yml
    repo-root/DESCRIPTION.md <- if dojo description is missing
    repo-root/module-id/module.yml <- fills in missing fields for module in dojo.yml (only module id *needs* to be in dojo.yml)
    repo-root/module-id/DESCRIPTION.md <- if module description is missing
    repo-root/module-id/challenge-id/challenge.yml <- fills in missing fields for challenge in higher-level ymls (only challenge id *needs* to be in dojo.yml/module.yml)
    repo-root/module-id/challenge-id/DESCRIPTION.md <- if challenge description is missing

    The higher-level details override the lower-level details.
    """

    setdefault_description(data, dojo_dir / "DESCRIPTION.md")

    for module_data in data.get("modules", []):
        if "id" not in module_data:
            continue

        module_dir = dojo_dir / module_data["id"]
        setdefault_subyaml(module_data, module_dir / "module.yml")
        setdefault_description(module_data, module_dir / "DESCRIPTION.md")
        setdefault_name(module_data)

        for challenge_data in module_data.get("challenges", []):
            if "id" not in challenge_data:
                continue

            challenge_dir = module_dir / challenge_data["id"]
            setdefault_subyaml(challenge_data, challenge_dir / "challenge.yml")
            setdefault_description(challenge_data, challenge_dir / "DESCRIPTION.md")
            setdefault_name(challenge_data)

    return data


def dojo_initialize_files(data: dict[str, Any], dojo_dir: Path):
    """
    Function to initialize the files specified by "files" in the yaml

    The function implements the admin-only "files" functionality not available for regular dojo creators.
    
    It does different things depending on the "type" attribute of "files":
        - If the type is "download": fetches the file from the "url" attribute and stores it in the "path".
            It ensures that the file is more than 50 MiB. Otherwise, it errors, saying that the file is small enough to be put in the github repo directly.
        - If the type is "text": creates the file the given "path" and writes everything in the "content" field into the file. This is mainly for testing purposes.
    """
    for dojo_file in data.get("files", []):
        assert is_admin(), "yml-specified files support requires admin privileges"
        rel_path = dojo_dir / dojo_file["path"]

        abs_path = dojo_dir / rel_path
        assert not abs_path.is_symlink(), f"{rel_path} is a symbolic link!"
        if abs_path.exists():
            continue
        abs_path.parent.mkdir(parents=True, exist_ok=True)

        if dojo_file["type"] == "download":
            urllib.request.urlretrieve(dojo_file["url"], str(abs_path))
            assert abs_path.stat().st_size >= 50*1024*1024, f"{rel_path} is small enough to fit into git ({abs_path.stat().st_size} bytes) --- put it in the repository!"
        if dojo_file["type"] == "text":
            with open(abs_path, "w") as o:
                o.write(dojo_file["content"])


def dojo_from_dir(dojo_dir: Path, *, dojo: typing.Optional[Dojos]=None) -> Dojos:
    """
    Creates a dojo from the specified directory, ensuring symlinks don't point outside the directory. The directory must contain a dojo.yml.
    """
    dojo_yml_path = dojo_dir / "dojo.yml"
    assert dojo_yml_path.exists(), "Missing file: `dojo.yml`"

    for path in dojo_dir.rglob("**"):
        assert dojo_dir == path or dojo_dir in path.resolve().parents, f"Error: symlink `{path}` references path outside of the dojo"

    data_raw = yaml.safe_load(dojo_yml_path.read_text())
    data = load_dojo_subyamls(data_raw, dojo_dir)
    dojo_initialize_files(data, dojo_dir)

    built_dojo = dojo_from_spec(data, dojo=dojo)

    validate_challenge_paths(built_dojo, dojo_dir)
    initialize_course(built_dojo, dojo_dir)

    return built_dojo


    
def validate_challenge_paths(dojo, dojo_dir):
    with dojo.located_at(dojo_dir):
        missing_challenge_paths = [
            challenge
            for module in dojo.modules
            for challenge in module.challenges
            if not challenge.path.exists()
        ]
        assert not missing_challenge_paths, "".join(
            f"Missing challenge path: {challenge.module.id}/{challenge.id}\n"
            for challenge in missing_challenge_paths)

def initialize_course(dojo, dojo_dir):
    course_yml_path = dojo_dir / "course.yml"
    if course_yml_path.exists():
        course = yaml.safe_load(course_yml_path.read_text())

        if "discord_role" in course and not dojo.official:
            raise AssertionError("Unofficial dojos cannot have a discord role")

        dojo.course = course

        students_yml_path = dojo_dir / "students.yml"
        if students_yml_path.exists():
            students = yaml.safe_load(students_yml_path.read_text())
            dojo.course["students"] = students

        syllabus_path = dojo_dir / "SYLLABUS.md"
        if "syllabus" not in dojo.course and syllabus_path.exists():
            dojo.course["syllabus"] = syllabus_path.read_text()

        grade_path = dojo_dir / "grade.py"
        if grade_path.exists():
            dojo.course["grade_code"] = grade_path.read_text()




def generate_ssh_keypair():
    temp_dir = tempfile.TemporaryDirectory()
    key_dir = pathlib.Path(temp_dir.name)

    public_key = key_dir / "key.pub"
    private_key = key_dir / "key"

    subprocess.run(["ssh-keygen",
                    "-t", "ed25519",
                    "-P", "",
                    "-C", "",
                    "-f", str(private_key)],
                    check=True,
                    capture_output=True)

    return (public_key.read_text().strip(), private_key.read_text())


def dojo_yml_dir(spec: str) -> tempfile.TemporaryDirectory:
    """
    Writes the spec into a file dojo.yml inside of a temporary directory as a means of creating a dojo without a github repository
    """
    yml_dir = tempfile.TemporaryDirectory(dir=DOJOS_TMP_DIR)    # TODO: ignore_cleanup_errors=True
    yml_dir_path = pathlib.Path(yml_dir.name)
    with open(yml_dir_path / "dojo.yml", "w") as do:
        do.write(spec)
    return yml_dir


def _assert_no_symlinks(dojo_dir):
    """
    Ensure that the given dojo_dir doesn't contain any symlinks that point outside of the dojo_dir
    """
    if not isinstance(dojo_dir, pathlib.Path):
        dojo_dir = pathlib.Path(dojo_dir)
    for path in dojo_dir.rglob("*"):
        assert dojo_dir == path or dojo_dir in path.resolve().parents, f"Error: symlink `{path}` references path outside of the dojo"


def dojo_clone(repository, private_key):
    """
    Clones the respository into DOJOS_TMP_DIR

    `repository` must be of format "username/repository-name".
    If the repository is public, it clones via https. If it is private, it uses the private_key to clone with ssh
    """
    tmp_dojos_dir = DOJOS_TMP_DIR
    tmp_dojos_dir.mkdir(exist_ok=True) # Creates the DOJOS_TMP_DIR if it doesn't already exist
    clone_dir = tempfile.TemporaryDirectory(dir=tmp_dojos_dir)  # TODO: ignore_cleanup_errors=True

    key_file = tempfile.NamedTemporaryFile("w")
    key_file.write(private_key)
    key_file.flush()

    url = f"https://github.com/{repository}"

    # If the github repository isn't public, the url is set so that cloning can be done over ssh
    if requests.head(url).status_code != 200:
        url = f"git@github.com:{repository}"

    subprocess.run(["git", "clone", "--depth=1", "--recurse-submodules", url, clone_dir.name],
                   env={
                       "GIT_SSH_COMMAND": f"ssh -i {key_file.name}",
                       "GIT_TERMINAL_PROMPT": "0",
                   },
                   check=True,
                   capture_output=True)

    _assert_no_symlinks(clone_dir.name)

    return clone_dir


def dojo_git_command(dojo, *args, repo_path=None):
    key_file = tempfile.NamedTemporaryFile("w")
    key_file.write(dojo.private_key)
    key_file.flush()

    if repo_path is None:
        repo_path = str(dojo.path)

    return subprocess.run(["git", "-C", repo_path, *args],
                          env={
                              "GIT_SSH_COMMAND": f"ssh -i {key_file.name}",
                              "GIT_TERMINAL_PROMPT": "0",
                          },
                          check=True,
                          capture_output=True)


def dojo_create(user: Users, repository: str, public_key: str, private_key: str , spec: str):
    """
    Attempts to create a dojo from the given github repository or specification string.

    Either repository or spec must be provided for successful dojo creation.
    If the provided repository is already used as a dojo, it will raise an AssertionError.
    Only admins of the platform are able to create a dojo from spec. From spec is mainly used for testing
    """
    try:
        if repository:
            repository_re = r"[\w\-]+/[\w\-]+"
            repository = repository.replace("https://github.com/", "")
            assert re.match(repository_re, repository), f"Invalid repository, expected format: <code>{repository_re}</code>"

            if Dojos.query.filter_by(repository=repository).first():
                raise AssertionError("This repository already exists as a dojo")

            dojo_dir = dojo_clone(repository, private_key)

        elif spec:
            assert is_admin(), "Must be an admin user to create dojos from spec rather than repositories"
            dojo_dir = dojo_yml_dir(spec)
            repository, public_key, private_key = None, None, None

        else:
            raise AssertionError("Repository or specification is required")

        dojo_path = pathlib.Path(dojo_dir.name)

        dojo = dojo_from_dir(dojo_path)
        dojo.repository = repository
        dojo.public_key = public_key
        dojo.private_key = private_key
        dojo.admins = [DojoAdmins(user=user)]

        db.session.add(dojo)
        db.session.commit()

        dojo.path.parent.mkdir(exist_ok=True)
        dojo_path.rename(dojo.path)
        dojo_path.mkdir()  # TODO: ignore_cleanup_errors=True

    except subprocess.CalledProcessError as e:
        deploy_url = f"https://github.com/{repository}/settings/keys"
        raise RuntimeError(f"Failed to clone: <a href='{deploy_url}' target='_blank'>add deploy key</a>")

    except IntegrityError:
        raise RuntimeError("This repository already exists as a dojo")

    except AssertionError as e:
        raise RuntimeError(str(e))

    # except Exception as e:
    #     print(f"Encountered error: {e}", file=sys.stderr, flush=True)
    #     raise RuntimeError("An error occurred while creating the dojo")

    return dojo


def dojo_update(dojo):
    if dojo.path.exists():
        old_commit = dojo_git_command(dojo, "rev-parse", "HEAD").stdout.decode().strip()

        tmp_dir = tempfile.TemporaryDirectory(dir=DOJOS_TMP_DIR)

        os.rename(str(dojo.path), tmp_dir.name)

        dojo_git_command(dojo, "fetch", "--depth=1", "origin", repo_path=tmp_dir.name)
        dojo_git_command(dojo, "reset", "--hard", "origin", repo_path=tmp_dir.name)
        dojo_git_command(dojo, "submodule", "update", "--init", "--recursive", repo_path=tmp_dir.name)

        try:
            _assert_no_symlinks(tmp_dir.name)
        except AssertionError:
            dojo_git_command(dojo, "reset", "--hard", old_commit, repo_path=tmp_dir.name)
            dojo_git_command(dojo, "submodule", "update", "--init", "--recursive", repo_path=tmp_dir.name)
            raise
        finally:
            os.rename(tmp_dir.name, str(dojo.path))
    else:
        tmpdir = dojo_clone(dojo.repository, dojo.private_key)
        os.rename(tmpdir.name, str(dojo.path))
    return dojo_from_dir(dojo.path, dojo=dojo)


def dojo_accessible(id: int) -> Dojos:
    if is_admin():
        return Dojos.from_id(id).first()
    return Dojos.viewable(id=id, user=get_current_user()).first()


def dojo_admins_only(func):
    signature = inspect.signature(func)
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        bound_args = signature.bind(*args, **kwargs)
        bound_args.apply_defaults()

        dojo = bound_args.arguments["dojo"]
        if not (dojo.is_admin(get_current_user()) or is_admin()):
            abort(403)
        return func(*bound_args.args, **bound_args.kwargs)
    return wrapper


def dojo_route(func):
    signature = inspect.signature(func)
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        bound_args = signature.bind(*args, **kwargs)
        bound_args.apply_defaults()

        dojo = dojo_accessible(bound_args.arguments["dojo"])
        if not dojo:
            abort(404)
        bound_args.arguments["dojo"] = dojo
        g.dojo = dojo

        if "module" in bound_args.arguments:
            module = DojoModules.query.filter_by(dojo=dojo, id=bound_args.arguments["module"]).first()
            if module is None:
                abort(404)
            bound_args.arguments["module"] = module

        return func(*bound_args.args, **bound_args.kwargs)
    return wrapper


def get_current_dojo_challenge(user=None):
    container = get_current_container(user)
    if not container:
        return None

    return (
        DojoChallenges.query
        .filter(DojoChallenges.id == container.labels.get("dojo.challenge_id"),
                DojoChallenges.module == DojoModules.from_id(container.labels.get("dojo.dojo_id"), container.labels.get("dojo.module_id")).first(),
                DojoChallenges.dojo == Dojos.from_id(container.labels.get("dojo.dojo_id")).first())
        .first()
    )
