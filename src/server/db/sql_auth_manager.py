import sqlite3
import os
# from ..logs.loggers import db_logger
from .password_hasher import PassswordHasher
import json

class SQLAuthManager:
    """
    -col: username
    -col: pasowrd
    -col: salt
    -col: blacklist
    -col: TLSTERMINATION vs TCPTunnel
    -col: Redirect vs 504BadRequest
    
    """
    def __init__(self):
        '''
        Defines where to save the data
        from the client and creates an sql table for it
        '''
        try:

            db_path = "D:/SafeProxy/src/server/db/.db/users.db"
            # db_path = os.getenv("DB_AUTH_TABLE_PATH")
            print(f"DB_PATH: {db_path}")
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.c = self.conn.cursor()

            self.c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                blacklist TEXT DEFAULT '[]',
                tls_terminate INTEGER DEFAULT 1,
                google_redirect INTEGER DEFAULT 1                   
            )''')

            self.conn.commit()
        except Exception as e:
            print(f"DB ERROR: Couldn't intialize/access table. {e}")


    def save_user(self, username, password):
        '''
        Saves the data from the user into the sql table
        that already exists.
        '''
        # Shouldn't happen, but incase an exsiitng usernmae passed, return
        if self.username_exist(username):
            return
        
        print(f"Username: {username}, password: {password}.")
        print('Hashing...')
        salt, pw_hash = PassswordHasher.hash_new_password(password)
        
        # Along with the pw, salt etc.. insert default prefrences (blacklist, tls_terminate, google_redirect)
        self.c.execute("INSERT INTO users \
        (username, password, salt, blacklist, tls_terminate, google_redirect) \
        VALUES (?, ?, ?, ?, ?, ?)",
        (username, pw_hash, salt, json.dumps([]), 1, 1))

        print(f"Added {username} to DB.")
        self.conn.commit()

    def username_exist(self, username) -> bool:
        '''
        Checks if the username exists in the sql table
        '''
        self.c.execute("SELECT 1 FROM users WHERE username = ? LIMIT 1", (username,))
        # fetchone() and not fetchall() since:
        # 1. In case no username found fetchone returns None while all() return []
        # 2. In case username found, fetchone rertruns `username` while fetchall retruns (username, ) as a tuple.
        # we only need to know IF a username exists and it's value. Therefore, fetchone
        # is more suitable for this case. 
        return self.c.fetchone() is not None 

    def check_psssword(self, username, password) -> bool:
        """
        Checks if the password is correct.
        """
        
        #hash password
        self.c.execute("SELECT password,salt FROM users WHERE username = ? LIMIT 1", (username,))
        
        resp = self.c.fetchone()

        if resp is None:
            return False

        hashed_password, salt = resp

        return PassswordHasher.is_correct_password(salt, password, hashed_password)

    def delete_user(self, username : str) -> bool:
        try:
            self.c.execute("DELETE FROM users where username = ?", (username, ))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Falied to delete {username}: {e}")
            return False

    def print_table(self):
        '''Prints the table'''
        self.c.execute("SELECT * FROM users")
        res = self.c.fetchall()
        print("----------USERS TABLE------------")
        for user in res:
            print(user)
        print("----------END TABLE------------")

if __name__ == "__main__":

    db= SQLAuthManager()
    db.delete_user("HelloThere")
    db.delete_user("jo")
    db.delete_user("bro")
    db.delete_user("krik")

    db.save_user("HelloThere", "1q2w3e")
    db.save_user("jo", "1q2w3e")
    db.save_user("bro", "aaaaa")
    db.save_user("krik", "1qw2e3e3r")
    # db.save_user("HelloThere", "Noedkf")
    db.print_table()
    print(db.username_exist("HelloThere"))
    db.check_psssword("jo" ,"1q2w3e")
    db.delete_user("HelloThere")
    db.print_table()