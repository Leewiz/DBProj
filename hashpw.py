__author__ = 'Leewiz'
import bcrypt
import psycopg2

db = psycopg2.connect(database='cs4332sm3', host='postgresql.cs.txstate.edu', user='dls228', password='55e8iifBoJNzbfX8w7wp')

def hashpw(dbc):
    hashed = []
    i =0
    with dbc.cursor() as cur:
        cur.execute('''
        SELECT password FROM users
        ''')
        for row in cur:
            hashed.append(bcrypt.hashpw(row[0].encode('UTF-8'), bcrypt.gensalt()))
        for hash in hashed:
            i+=1
            cur.execute('''
            UPDATE users SET password = %s WHERE user_id = %s
            ''', (hash.decode('UTF-8'), i))
            db.commit()

hashpw(db)