import sqlite3 as lite
import flask
app = flask.Flask(__name__)
import jinja2
engine = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'))


@app.route('/', methods=['GET'])
def login():
    userInfo = flask.request.form
    print(userInfo);
    return engine.get_template('login.html').render()

if __name__ == '__main__':
app.run()
