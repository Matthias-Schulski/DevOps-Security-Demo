from flask import Flask, request, redirect, make_response
import sqlite3
import urllib
import quoter_templates as templates
import html # Geïmporteerd om HTML-escaping mogelijk te maken

# Run using `poetry install && poetry run flask run --reload`
app = Flask(__name__)
app.static_folder = '.'

# Open the database. Have queries returns dicts instead of tuples.
# The use of `check_same_thread` can cause unsexpected results in rare cases. We'll
# get rid of this when we learn about SQLAlchemy.
db = sqlite3.connect("db.sqlite3", check_same_thread=False)
db.row_factory = sqlite3.Row

# Log all requests for analytics purposes
log_file = open('access.log', 'a', buffering=1)
@app.before_request
def log_request():
    log_file.write(f"{request.method} {request.path} {dict(request.form) if request.form else ''}\n")


# Set user_id on request if user is logged in, or else set it to None.
@app.before_request
def check_authentication():
    if 'user_id' in request.cookies:
        request.user_id = int(request.cookies['user_id'])
    else:
        request.user_id = None


# The main page
@app.route("/")
def index():
    quotes = db.execute("select id, text, attribution from quotes order by id").fetchall()
    
    # Oude situatie - Kwetsbaar voor Cross-site Scripting (XSS)
    # Melding: CWE-79 - Unsanitized input from an HTTP parameter flows into the return value.
    # return templates.main_page(quotes, request.user_id, request.args.get('error'))

    # Oplossing: De 'error' parameter wordt gesanitized met html.escape() voordat deze
    # aan de template wordt doorgegeven. Dit converteert potentieel gevaarlijke
    # karakters (zoals <, >) naar hun veilige HTML-equivalenten (&lt;, &gt;).,
    # waardoor een XSS-aanval wordt voorkomen.
    error_message = request.args.get('error')
    safe_error_message = html.escape(error_message) if error_message else None
    return templates.main_page(quotes, request.user_id, safe_error_message)


# The quote comments page
@app.route("/quotes/<int:quote_id>")
def get_comments_page(quote_id):
    # Oude situatie - Kwetsbaar voor SQL Injection
    # Melding: CWE-89 - Unsanitized input flows into execute.
    # quote = db.execute(f"select id, text, attribution from quotes where id={quote_id}").fetchone()
    # comments = db.execute(f"select text, datetime(time,'localtime') as time, name as user_name from comments c left join users u on u.id=c.user_id where quote_id={quote_id} order by c.id").fetchall()
    
    # Oplossing: Gebruik geparametriseerde queries met '?' als placeholder om input
    # veilig door te geven aan de database. Dit voorkomt dat de input als SQL-code
    # wordt uitgevoerd.
    quote = db.execute("select id, text, attribution from quotes where id=?", (quote_id,)).fetchone()
    comments = db.execute("select text, datetime(time,'localtime') as time, name as user_name from comments c left join users u on u.id=c.user_id where quote_id=? order by c.id", (quote_id,)).fetchall()
    
    return templates.comments_page(quote, comments, request.user_id)


# Post a new quote
@app.route("/quotes", methods=["POST"])
def post_quote():
    with db:
        # Oude situatie - Kwetsbaar voor SQL Injection
        # Melding: CWE-89 - Unsanitized input from a web form flows into execute.
        # db.execute(f"""insert into quotes(text,attribution) values("{request.form['text']}","{request.form['attribution']}")""")

        # Oplossing: Gebruik geparamdetriseerde queries om formulierdata veilig in de database in te voegen.
        db.execute(
            "insert into quotes(text,attribution) values(?,?)",
            (request.form['text'], request.form['attribution'])
        )
    return redirect("/#bottom")


# Post a new comment
@app.route("/quotes/<int:quote_id>/comments", methods=["POST"])
def post_comment(quote_id):
    with db:
        # Oude situatie - Kwetsbaar voor SQL Injection
        # Melding: CWE-89 - Unsanitized input from a web form flows into execute.
        # db.execute(f"""insert into comments(text,quote_id,user_id) values("{request.form['text']}",{quote_id},{request.user_id})""")
        
        # Oplossing: Gebruik geparametriseerde queries om commentaardata veilig in te voegen.
        db.execute(
            "insert into comments(text,quote_id,user_id) values(?,?,?)",
            (request.form['text'], quote_id, request.user_id)
        )
    return redirect(f"/quotes/{quote_id}#bottom")


# Sign in user
@app.route("/signin", methods=["POST"])
def signin():
    username = request.form["username"].lower()
    password = request.form["password"]

    # Oude situatie - Kwetsbaar voor SQL Injection
    # Melding: CWE-89 - Unsanitized input from a web form flows into execute.
    # user = db.execute(f"select id, password from users where name='{username}'").fetchone()
    
    # Oplossing: Gebruik een geparametriseerde query voor de SELECT-statement.
    user = db.execute("select id, password from users where name=?", (username,)).fetchone()

    if user: # user exists
        if password != user['password']:
            # wrong! redirect to main page with an error message
            return redirect('/?error='+urllib.parse.quote("Invalid password!"))
        user_id = user['id']
    else: # new sign up
        with db:
            # Oude situatie - Kwetsbaar voor SQL Injection
            # Melding: CWE-89 - Unsanitized input from a web form flows into execute.
            # cursor = db.execute(f"insert into users(name,password) values('{username}', '{password}')")
            
            # Oplossing: Gebruik een geparametriseerde query voor de INSERT-statement.
            cursor = db.execute(
                "insert into users(name,password) values(?, ?)",
                (username, password)
            )
            user_id = cursor.lastrowid
    
    response = make_response(redirect('/'))
    response.set_cookie('user_id', str(user_id))
    return response


# Sign out user
@app.route("/signout", methods=["GET"])
def signout():
    response = make_response(redirect('/'))
    response.delete_cookie('user_id')
    return response