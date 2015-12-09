import psycopg2
import flask
import bcrypt
from contextlib import contextmanager
from datetime import datetime

app = flask.Flask(__name__)
app.config.from_pyfile('Settings.py')
db = psycopg2.connect(**app.config['PG_ARGS'])


def db_connect(app):

    """
    Create a database connection.
    :param app: The Flask application.
    :return: The database connection
    """
    # Get the database connection from the configuration
    cxn = psycopg2.connect(**app.config['PG_ARGS'])
    #
    cxn.autocommit = False
    return cxn


@contextmanager
def db_cursor(app):
    """
    Create a database connection and cursor.
    :param app: The application.
    :return: A database cursor that, when closed, also closes its connection.
    """
    dbc = db_connect(app)
    try:
        cur = dbc.cursor()
        try:
            yield cur
        finally:
            cur.close()
    finally:
        dbc.close()


def not_following(auth_user, uid):
    cur = db.cursor()
    cur.execute('''
        SELECT follower_id, followee_id
        FROM follow
        WHERE follower_id = %s AND followee_id = %s
        ''', (auth_user, uid))
    row = cur.fetchone()
    if not_following:
        pass #return True


def get_user(dbc, uid):
    """
    Get a user's information.
    :param dbc: A database connection.
    :param uid: The user ID.
    :return: The user information map, or None if the user is invalid.
    """
    with dbc.cursor() as cur:
        cur.execute('''
            SELECT display_name
            FROM users WHERE user_id = %s
        ''', (uid,))
        row = cur.fetchone()
        if row is None:
            return None
        else:
            name, = row
            return {'name': name, 'id': uid }


def lookup_user(dbc, name):
    """
    Look up a user by name.
    :param dbc: A database connection.
    :param uid: The user ID.
    :return: The user information map, or None if the user is invalid.
    """
    with dbc.cursor() as cur:
        cur.execute('''
            SELECT user_id, username, password
            FROM users WHERE username = %s
        ''', (name,))
        row = cur.fetchone()
        if row is None:
            return None
        else:
            uid, name, pw_hash = row
            return {'name': name, 'id': uid, 'pw_hash': pw_hash }


def check_auth(dbc, username, password):
    """
    Check if a user is authorized.
    :param dbc: The database connection.
    :param username: The user name.
    :param password: The password (unhashed).
    :return: The user ID, or None if authentication failed.
    """
    user = lookup_user(dbc, username)
    if user is None:
        return None
    hash = bcrypt.hashpw(password.encode('UTF-8'),
                         user['pw_hash'].encode('UTF-8'))
    if hash == user['pw_hash'].encode('UTF-8'):
        return user['id']
    else:
        return None


def create_user(dbc, username, password, email, display_name):
    """
    Creates a user.
    :param dbc: The DB connection.
    :param username: The user name.
    :param password: The password.
    :return: The user ID.
    """
    hash = bcrypt.hashpw(password.encode('UTF-8'), bcrypt.gensalt())
    with dbc.cursor() as cur:
        cur.execute('''
            INSERT INTO users (username, password, display_name, email)
            VALUES (%s, %s, %s, %s)
            RETURNING user_id
        ''', (username, hash.decode('UTF-8'), display_name, email))
        row = cur.fetchone()
        dbc.commit()
        return row[0]


def add_bug(dbc, uid, form):
    with dbc.cursor() as cur:
        if form['title'] and form['detail'] and form['tags'] and form['assignee']:
            cur.execute('START TRANSACTION')
            title = form['title'].strip()
            detail = form['detail'].strip()
            tags = form['tags'].split(',')
            assignee = form['assignee'].strip()
        else:
            return None
        cur.execute('''
        SELECT user_id FROM users WHERE username=%s
        ''', (assignee,))
        #if cur.fetchone() is not None:
        assignee_id = cur.fetchone()[0]
        #else:
        #    return ''
        cur.execute('''
            INSERT INTO bug
              (creator_id, title, detail, creation_date, status, tags, assignee_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING bug_id
        ''', (uid, title, detail, datetime.now().date(), 1, tags, assignee_id))
        bid = cur.fetchone()[0]
        for tag in tags:
            cur.execute('''
                INSERT INTO tag (bug_id, text) VALUES (%s, %s)
            ''', (bid, tag.strip().lower()))
        dbc.commit()
        return bid


def add_comment(dbc, uid, bid, form):
    with dbc.cursor() as cur:
        cur.execute('START TRANSACTION')
        text = form['text'].strip()
        date = datetime.now()
        if not text:
            text = None
            return None
        cur.execute('''
            INSERT INTO comments
              (user_id, bug_id, text, dates)
            VALUES (%s, %s, %s, %s)
            RETURNING comment_id
        ''', (uid, bid, text, date))
        cid = cur.fetchone()[0]
        dbc.commit()


def get_comment(dbc, bid):
    with dbc.cursor() as cur:
        cur.execute('''
            SELECT bug_id, display_name, text, dates, user_id
            FROM comments JOIN users
            USING (user_id)
            WHERE bug_id = %s
            ''',(bid,))
        comment = []
        if comment is None:
            return None
        for bug_id, display_name, text, dates, uid in cur:
         comment.append({'bug_id' : bug_id, 'display_name' : display_name, 'text': text, 'dates' : dates, 'uid': uid })

        return comment


def get_bug(dbc, bid):
   with dbc.cursor() as cur:
       cur.execute('''
           SELECT title, detail, vote, status, creator_id, display_name
           FROM bug
           JOIN users ON (creator_id=user_id)
           WHERE bug_id = %s
       ''', (bid,))
       row = cur.fetchone()
       if row is None:
           return None

       title, detail, vote, status, cid, cname = row
       bug = { 'id': bid, 'title': title,
                'detail': detail, 'tags': [],
               'vote': vote, 'status': status,
               'cid': cid, 'cname': cname}

       cur.execute('''
           SELECT text FROM tag WHERE bug_id = %s
       ''', (bid,))
       for tag, in cur:
           bug['tags'].append(tag)
       return bug


def getBugByUID(dbc, uid):
    with dbc.cursor() as cur:
        cur.execute('''SELECT title, bug_id
                       FROM bug
                       JOIN users on users.user_id = bug.creator_id
                       WHERE user_id = %s''', [uid])
        bug = []
        for title, bid in cur:
            bug.append({'title' : title, 'bid' : bid})
    return bug


def searchBugsByTitle(dbc, search):
    with dbc.cursor() as cur:
        cur.execute('''SELECT title, bug_id, creation_date
                       FROM bug
                       WHERE title = %s
                    ''', (search,))
        bug = cur.fetchone()
    return bug


def searchBugsByTag(dbc, search):
    search = '%'+search+'%'
    with dbc.cursor() as cur:
        cur.execute('''SELECT title, bug_id, creation_date
                       FROM bug
                       WHERE tags LIKE %s
                        ''', (search,))
        bug = []
        for title, bid, cdate in cur:
            bug.append({'title': title, 'bid': bid, 'cdate': cdate})
    return bug


def getVote(dbc, bid):
    with dbc.cursor() as cur:
        cur.execute(''' SELECT vote
                        FROM bug
                        WHERE bug_id = %s
                       ''')
        votes = cur.fetchone()
    return votes


def updateVote(dbc, bid, votes):
    with dbc.cursor() as cur:
        cur.execute(''' UPDATE bug
                        SET vote = %s
                        WHERE bug_id = %s
                   ''', (votes, bid))
        dbc.commit()
    return votes


def get_assigned_bugs(dbc, uid):
    with dbc.cursor() as cur:
        cur.execute(''' SELECT title, bug_id
                        FROM bug
                        WHERE assignee_id=%s
        ''', (uid,))
        bugs = []
        for title, bid in cur:
            bugs.append({'title' : title, 'bid' : bid})
        return bugs


def get_assignee(dbc, bid):
    with dbc.cursor() as cur:
        cur.execute(''' SELECT display_name, assignee_id
                        FROM users
                        JOIN bug
                        ON assignee_id=user_id
                        WHERE bug_id=%s
                    ''', (bid,))
        row = cur.fetchone()
        if row is None:
            return None
        assignee_name, assignee_id = row
        assignee = {'assignee': assignee_name, 'assignee_id': assignee_id}
        return assignee


def update_status(dbc,status, bid):
    with dbc.cursor() as cur:
        cur.execute(''' UPDATE bug
                        SET status = %s
                        WHERE bug_id = %s
                    ''', (status, bid))
        dbc.commit()
    return bid


def update_title(dbc, newtitle, bid):
    print newtitle
    with dbc.cursor() as cur:
        cur.execute(''' UPDATE bug
                        SET title = %s
                        WHERE bug_id = %s
                    ''', (newtitle, bid))
        dbc.commit()
    return bid


def update_desc(dbc,newdesc, bid):
    with dbc.cursor() as cur:
        cur.execute(''' UPDATE bug
                        SET detail = %s
                        WHERE bug_id = %s
                    ''', (newdesc, bid))
        dbc.commit()
    return bid


def check_username(dbc, username):
    with dbc.cursor() as cur:
        cur.execute(''' SELECT username
                        FROM users
                        WHERE username=%s
                    ''', (username,))
        username=cur.fetchone()
        return username


def check_email(dbc, email):
    with dbc.cursor() as cur:
        cur.execute(''' SELECT email
                        FROM users
                        WHERE email=%s
                    ''', (email,))
        email=cur.fetchone()
        return email