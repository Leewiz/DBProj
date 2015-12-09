import flask
import psycopg2
import func

app = flask.Flask(__name__)
app.config.from_pyfile('Settings.py')
db = psycopg2.connect(**app.config['PG_ARGS'])


@app.route('/')
def hello_world():
    if 'auth_user' in flask.session:
        # we have a user
        with func.db_connect(app) as db:
            uid = flask.session['auth_user']
            user = func.get_user(db, uid)
            if user is None:
                app.logger.error('invalid user %d', uid)
                flask.abort(400)
            return flask.redirect(flask.url_for('profile', uid=flask.session['auth_user']))
    else:
        return flask.render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    username = flask.request.form['username']
    password = flask.request.form['passwd']
    if username is None or password is None:
        flask.abort(400)
    action = flask.request.form['action']
    if action == 'Log in':
        with func.db_connect(app) as db:
            uid = func.check_auth(db, username, password)
            if uid is not None:
                flask.session['auth_user'] = uid
                return flask.redirect(flask.url_for('profile', uid=flask.session['auth_user']))
            else:
                flask.abort(403)
    elif action == 'Create account':
            return flask.redirect('/create', code=303)


@app.route('/create', methods=['GET', 'POST'])
def create_user():
    if flask.request.method=='GET':
        return flask.render_template('createuser.html')
    else:
        action = flask.request.form['action']
        if action == 'Create':
            username = flask.request.form['username'].strip()
            display_name = flask.request.form['displayname'].strip()
            password = flask.request.form['password'].strip()
            email = flask.request.form['email'].strip()
            if not username or not password or not email or not display_name:
                return flask.render_template('createuser.html', fail=1)
            checkun = func.check_username(db, username)
            if checkun is not None:
                return flask.render_template('createuser.html', fail=2)
            checkemail = func.check_email(db, email)
            if checkemail is not None:
                return flask.render_template('createuser.html', fail=3)
            flask.session['auth_user']=func.create_user(db, username, password, email, display_name)
    return flask.redirect(flask.url_for('profile', uid=flask.session['auth_user']))


@app.route('/profile/<int:uid>', methods=['GET', 'POST'])
def profile(uid):
    if flask.request.form == 1:
        if flask.session['auth_user'] != uid:
            if func.not_following(flask.session['auth_user'], uid):
                func.follow(flask.session['auth_user'], uid)
            else:
                print("Already following this user.")
        else:
            print("Can't follow yourself.")

    users = func.get_user(db, uid)
    bugs = func.getBugByUID(db, uid)
    assigned_bugs = func.get_assigned_bugs(db, uid)
    return flask.render_template('profile.html',
                                 users = users,
                                 bugs = bugs,
                                 assigned_bugs=assigned_bugs)


@app.route('/add', methods=['GET', 'POST'])
def add_bug():
    if 'auth_user' in flask.session:
        uid = flask.session['auth_user']
    else:
        flask.abort(403)
    if flask.request.method == 'GET':
        return flask.render_template('new-bug.html', uid=uid)
    else:
        with func.db_connect(app) as dbc:
            bid = func.add_bug(dbc, uid, flask.request.form)
            if bid is None:
                return flask.render_template('new-bug.html', uid=uid, bid=bid)
            elif bid=='':
                return flask.render_template('new-bug.html', uid=uid, bid=bid)
    return flask.redirect(flask.url_for('viewbug', bid=bid))


@app.route('/viewbug/<int:bid>', methods=['GET', 'POST'])
def viewbug(bid):
    if flask.request.method == 'GET':
        bug = func.get_bug(db, bid)
        assignee = func.get_assignee(db, bid)
        if 'auth_user' in flask.session:
            auth_user=flask.session['auth_user']
        else:
            auth_user=0
        return flask.render_template('viewbug.html',
                                     bid=bid, title = bug['title'],
                                     description = bug['detail'],
                                     votes=bug['vote'],
                                     tags=bug['tags'],
                                     comments=func.get_comment(db, bid),
                                     assignee=assignee['assignee'],
                                     assignee_id=assignee['assignee_id'],
                                     status=bug['status'],
                                     cid=bug['cid'],
                                     cname=bug['cname'],
                                     auth_user=auth_user)


    if flask.request.method == 'POST':
        bug = func.get_bug(db, bid)
        action = flask.request.form['action']
        assignee = func.get_assignee(db, bid)
        uid = flask.session['auth_user']
        with func.db_connect(app) as dbc:
            if action == 'Upvote':
                oldvote = bug['vote']
                oldvote+=1
                func.updateVote(dbc, bid, oldvote)
            elif action == 'Downvote':
                oldvote = bug['vote']
                oldvote-=1
                func.updateVote(dbc, bid, oldvote)
            elif action == 'Comment':
                func.add_comment(dbc, uid, bid, flask.request.form)
    return flask.redirect(flask.url_for ('viewbug', bid=bid))


@app.route('/logout')
def logout():
    flask.session.pop('auth_user', None)
    flask.flash('You have been successfully logged out.')
    return flask.redirect('/')


@app.route('/search', methods=['GET', 'POST'])
def search():
    if flask.request.method == 'GET':
        return flask.render_template('search_bug.html')

    if flask.request.method == 'POST':
        action = flask.request.form['action']
        with func.db_connect(app) as dbc:
            if action == 'search':
                results = func.searchBugsByTitle(dbc, flask.request.form['query'])
                if results is None:
                    pass
                else:
                    title = results[0]
                    bid = results[1]
                    cdate = results[2]
                    print results
                    results = func.searchBugsByTag(db, flask.request.form['query'])
                    print results
                    return flask.render_template('search_bug.html',
                                                 results=results,
                                                 title=title,
                                                 bid=bid,
                                                 cdate=cdate)
                results = func.searchBugsByTag(db, flask.request.form['query'])
                return flask.render_template('search_bug.html', results=results)


@app.route('/editbug/<int:bid>', methods=['GET', 'POST'])
def editbug(bid):
    if flask.request.method == 'GET':
        assignee = func.get_assignee(db, bid)
        bug = func.get_bug(db, bid)
        votes =  bug['vote']
        comments = func.get_comment(db, bid)
        return flask.render_template('viewbugedit.html',
                                     bid=bid, title = bug['title'],
                                     description = bug['detail'],
                                     votes=bug['vote'],
                                     tags=bug['tags'],
                                     comments=func.get_comment(db, bid),
                                     assignee=assignee['assignee'],
                                     assignee_id=assignee['assignee_id'],
                                     status=bug['status'],
                                     cid=bug['cid'],
                                     cname=bug['cname'],
                                     auth_user=flask.session['auth_user'])
    if flask.request.method == 'POST':
        bug = func.get_bug(db, bid)
        action = flask.request.form['action']
        assignee = func.get_assignee(db, bid)
        uid = flask.session['auth_user']
        with func.db_connect(app) as dbc:
            if action == 'Close Bug':
                status = 1
                func.update_status(dbc, status, bid)
            elif action == 'Submit New Title':
                newtitle = flask.request.form['title']
                func.update_title(dbc, newtitle, bid)
            elif action == 'Submit New Description':
                newdesc = flask.request.form['description']
                func.update_desc(dbc, newdesc, bid)
    return flask.redirect(flask.url_for('viewbug', bid=bid))


if __name__ == '__main__':
    app.run()

