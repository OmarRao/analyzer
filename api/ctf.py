"""
VulnBank - CTF Scoring Mode
Capture The Flag scoring for VulnBank security training exercises.
"""

import time
from flask import Blueprint, request, jsonify, session
from services.firebase_tracker import track_ctf_submission

ctf_bp = Blueprint("ctf", __name__)

FLAGS = {
    "sqli": "FLAG{sql_1nj3ct10n_m4st3r}",
    "xss": "FLAG{xss_r3fl3ct3d_w1n}",
    "ssrf": "FLAG{ssrf_int3rn4l_acc3ss}",
    "idor": "FLAG{id0r_acc0unt_t4k30v3r}",
    "xxe": "FLAG{xxe_f1l3_r34d}",
    "ssti": "FLAG{ssti_rce_4ch13v3d}",
    "jwt": "FLAG{jwt_4lg_c0nfus10n}",
    "ldap": "FLAG{ldap_1nj3ct10n_byp4ss}",
    "pickle": "FLAG{p1ckl3_rc3_3xpl01t}",
    "nosql": "FLAG{n0sql_1nj3ct10n_byp4ss}",
    "business": "FLAG{bus1n3ss_l0g1c_fl4w}",
}

HINTS = {
    "sqli": "Try adding a single quote to the login username field. What does the error tell you?",
    "xss": "The search endpoint reflects your input. What happens if you search for <script>alert(1)</script>?",
    "ssrf": "The /api/fetch endpoint fetches any URL. What internal IP ranges are often used for cloud metadata?",
    "idor": "Try changing the account_id in /api/accounts/<id>. Does the server check if the account belongs to you?",
    "xxe": "The XML parser resolves external entities. Look up how to define a SYSTEM entity pointing to file:///etc/passwd.",
    "ssti": "The template engine evaluates {{ expressions }}. Try {{ 7*7 }} first, then escalate to os.popen.",
    "jwt": "Decode a JWT and look at the 'alg' header. What happens if you change it to 'none' and remove the signature?",
    "ldap": "LDAP filters use special characters. Try injecting *)(&  as the username to collapse the AND filter.",
    "pickle": "Python pickle deserializes arbitrary objects. Craft a class with __reduce__ returning (os.system, ('cmd',)).",
    "nosql": "MongoDB accepts query operators as JSON. Try {'password': {'$ne': ''}} to bypass password checks.",
    "business": "Try sending a negative amount to /api/transfer/overdraft. Does the server validate the sign of the amount?",
}

CATEGORIES = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "ssrf": "Server-Side Request Forgery",
    "idor": "Insecure Direct Object Reference",
    "xxe": "XML External Entity",
    "ssti": "Server-Side Template Injection",
    "jwt": "JWT Algorithm Confusion",
    "ldap": "LDAP Injection",
    "pickle": "Insecure Deserialization",
    "nosql": "NoSQL Injection",
    "business": "Business Logic Flaws",
}

# In-memory scoreboard: {team: {"score": int, "solved": [category,...], "first_solve_time": float}}
_scoreboard = {}


@ctf_bp.route("/api/ctf/flags", methods=["GET"])
def list_flags():
    """Returns list of flag names and categories (not values)."""
    return jsonify({
        "flags": [
            {"category": cat, "name": CATEGORIES[cat], "points": 100}
            for cat in FLAGS
        ],
        "total_flags": len(FLAGS),
        "total_points": len(FLAGS) * 100
    })


@ctf_bp.route("/api/ctf/submit", methods=["POST"])
def submit_flag():
    """
    Submit a captured flag for scoring.
    Body: {"team": "TeamName", "flag": "FLAG{...}"}
    """
    data = request.get_json(force=True) or {}
    team = data.get("team", "").strip()
    submitted_flag = data.get("flag", "").strip()

    if not team:
        return jsonify({"error": "team name required"}), 400
    if not submitted_flag:
        return jsonify({"error": "flag required"}), 400

    # Find which category this flag belongs to
    matched_category = None
    for cat, flag_val in FLAGS.items():
        if flag_val == submitted_flag:
            matched_category = cat
            break

    if not matched_category:
        anon_id = session.get("_anon_id", team)
        track_ctf_submission(anon_id, team, "unknown", False)
        return jsonify({"correct": False, "message": "Incorrect flag. Keep trying!"}), 200

    # Initialize team entry
    if team not in _scoreboard:
        _scoreboard[team] = {"score": 0, "solved": [], "first_solve_time": time.time()}

    team_data = _scoreboard[team]

    if matched_category in team_data["solved"]:
        anon_id = session.get("_anon_id", team)
        track_ctf_submission(anon_id, team, matched_category, True)
        return jsonify({
            "correct": True,
            "message": f"Flag already submitted for category: {CATEGORIES[matched_category]}",
            "duplicate": True
        })

    # Award points
    team_data["solved"].append(matched_category)
    team_data["score"] += 100

    anon_id = session.get("_anon_id", team)
    track_ctf_submission(anon_id, team, matched_category, True)

    return jsonify({
        "correct": True,
        "message": f"Correct! {CATEGORIES[matched_category]} flag captured!",
        "category": matched_category,
        "points_awarded": 100,
        "total_score": team_data["score"],
        "flags_captured": len(team_data["solved"])
    })


@ctf_bp.route("/api/ctf/scoreboard", methods=["GET"])
def scoreboard():
    """Returns team scores sorted by score descending, then time ascending."""
    board = []
    for team, data in _scoreboard.items():
        board.append({
            "team": team,
            "score": data["score"],
            "flags_captured": len(data["solved"]),
            "categories_solved": [CATEGORIES[c] for c in data["solved"]],
            "first_solve_time": data["first_solve_time"]
        })

    board.sort(key=lambda x: (-x["score"], x["first_solve_time"]))

    return jsonify({
        "scoreboard": board,
        "total_teams": len(board),
        "max_possible_score": len(FLAGS) * 100
    })


@ctf_bp.route("/api/ctf/hints/<category>", methods=["GET"])
def get_hint(category):
    """Returns a hint for the specified vulnerability category."""
    if category not in HINTS:
        return jsonify({
            "error": f"Unknown category: {category}",
            "valid_categories": list(CATEGORIES.keys())
        }), 404

    return jsonify({
        "category": category,
        "name": CATEGORIES[category],
        "hint": HINTS[category],
        "flag_format": "FLAG{...}",
        "points": 100
    })
