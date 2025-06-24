import collections

from flask import Blueprint, render_template, redirect, url_for
from CTFd.models import db
from CTFd.utils.user import get_current_user
from CTFd.utils.decorators import authed_only, admins_only

from ..models import DojoChallenges, Dojos, DojoAdmins, DojoMembers
from ..utils.dojo import generate_ssh_keypair
from ..utils.stats import get_container_stats

dojos = Blueprint("pwncollege_dojos", __name__)


@dojos.route("/dojos")
def listing(template="dojos.html"):
    """
    Route for displaying all of the available dojos to the user. This is what renders "/" (the front page) as well as "/dojos"

    It calculates the following dojo information and passes it along to the template renderer:
        - Pairs each dojo with the number of solves that the currently logged in user has on each dojo
        - Groups each dojo based on the dojo's dojo.type. 
        - Counts the number of people solving each dojo at the current moment
    
    The grouping determine where in the front page the dojos get placed. These are determined by the dojo.type:
        - Type "welcome" gets placed under "Getting Started" (white belt material)
        - Type "topic" gets placed under "Core Material"
        - Type "public" gets placed under "Community Material"
        - Type "course" gets placed under "The Courses"

    Dojos in the "member" list get placed under "Dojos You've Joined". This is usually for private dojos or dojos that you joined as courses.
    Dojos in the "admin" list are simply dojos of which the current user is an admin
    """
    categorized_dojos = {
        "welcome": [],
        "topic": [],
        "public": [],
        "course": [],
        "member": [],
        "admin": [],
    }

    user = get_current_user()
    user_dojo_admins = []
    user_dojo_members = []
    dojo_solves = (
        Dojos.viewable(user=user)
        .options(db.undefer(Dojos.modules_count), db.undefer(Dojos.challenges_count))
    )
    if user:
        solves_subquery = (
            DojoChallenges.solves(user=user, ignore_visibility=True, ignore_admins=False)
            .group_by(DojoChallenges.dojo_id)
            .with_entities(DojoChallenges.dojo_id, db.func.count().label("solve_count"))
            .subquery()
        )
        dojo_solves = (
            dojo_solves
            .outerjoin(solves_subquery, Dojos.dojo_id == solves_subquery.c.dojo_id)
            .add_columns(db.func.coalesce(solves_subquery.c.solve_count, 0).label("solve_count"))
        )
        user_dojo_admins = DojoAdmins.query.where(DojoAdmins.user_id == user.id).all()
        user_dojo_members = DojoMembers.query.where(DojoMembers.user_id == user.id).all()
    else:
        dojo_solves = dojo_solves.add_columns(0)

    for dojo, solves in dojo_solves:
        if not (dojo.type == "hidden" or (dojo.type == "example" and dojo.official)):
            categorized_dojos.setdefault(dojo.type, []).append((dojo, solves))
            # If a user joined or created a private dojo, this ensures that shows up under "Dojos you've joined" even if it shows up elsewhere on the front page
            # It also displays the solve count as 0 under "Dojos you've joined"
            categorized_dojos["member"].extend((dojo_member.dojo, 0) for dojo_member in user_dojo_members
                                               if dojo_member.dojo == dojo and dojo.type not in ["welcome", "topic", "public"])
        categorized_dojos["admin"].extend((dojo_admin.dojo, 0) for dojo_admin in user_dojo_admins if dojo_admin.dojo == dojo)

    # Retrieves count for the number of containers 
    dojo_container_counts = collections.Counter(stats["dojo"] for stats in get_container_stats())

    return render_template(template, user=user, categorized_dojos=categorized_dojos, dojo_container_counts=dojo_container_counts)


@dojos.route("/dojos/create")
@authed_only
def dojo_create():
    public_key, private_key = generate_ssh_keypair()
    return render_template(
        "dojo_create.html",
        public_key=public_key,
        private_key=private_key,
        example_dojos=Dojos.viewable().where(Dojos.data["type"] == "example").all()
    )




@dojos.route("/admin/dojos")
@admins_only
def view_all_dojos():
    return render_template("admin_dojos.html", dojos=Dojos.query.order_by(*Dojos.ordering()).all())


def dojos_override():
    return redirect(url_for("pwncollege_dojos.listing"), code=301)
