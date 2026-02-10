import sqlite3
import json
import os
import threading

from ..logs.loggers import db_logger
from .password_hasher import PassswordHasher

class SQLAuthManager:
    """

    """
    def __init__(self):
        '''
        Defines where to save the data
        from the client and creates an sql table for it
        '''
        try:

            db_path = os.getenv("DB_AUTH_TABLE_PATH")
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL;") # lets reading and writing ewithout locking the file
            self._thread_local= threading.local()
            # each handler (HTTPHandler, HttpsTlsTerminationHnalder, TcpHandler) uses the DB
            # to decide what to do => TLS terminate/TCP handler, blacklist fetching from DB, and 504 vs redirect
            # This creates an error - differnet handlers (on different threads) use the same cursor
            # obj to fetch data from table resulting in sqlite3.ProgrammingError: Recursive use of cursors not allowed.
            # Two solutions:
            # 1. Lock threading the DB - makes the proxy really slow and one-threaded instead of a concurrent one
            # 2. creating a differnet cursor (not connection!) for each thread - This might be a good solution
            # as it allows DB access conncurrenty for differnet threads.
            

            self.c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                blacklist TEXT,
                tls_terminate INTEGER DEFAULT 0,
                google_redirect INTEGER DEFAULT 0                   
                )
                '''
            )

            self.conn.commit()
            db_logger.info(f"DB initalized successfully.")
        except Exception as e:
            db_logger.critical(f"Couldn't intialize/access table: {e}", exc_info=True)

    @property
    def c(self) -> sqlite3.Cursor:
        # get a new cursor for each thread
        if not hasattr(self._thread_local, "cursor"):
            self._thread_local.cursor = self.conn.cursor()
        return self._thread_local.cursor
    
    # --- AUTH FUNCTIONS ---

    def save_user(self, username  : str, password : str):
        '''
        Saves a new user in the DB
        '''
        try:
            # Shouldn't happen, but incase an existing usernmae passed, return.
            if self.username_exist(username):
                db_logger.info('Username already exists.')
                return
            
            salt, pw_hash = PassswordHasher.hash_new_password(password)
            db_logger.debug(f'Hashed {username}\'s password.')
            
            # Along with the pw, salt etc.. insert default prefrences (blacklist, tls_terminate, google_redirect)
            self.c.execute(
            "INSERT INTO users \
            (username, password, salt, blacklist, tls_terminate, google_redirect) \
            VALUES (?, ?, ?, ?, ?, ?)",
            (username, pw_hash, salt, json.dumps({}), 1, 1)
            )

            self.conn.commit()
            db_logger.info(f"Added {username} to DB.")
        except Exception as e:
            db_logger.error(f"Failed saving {username} to DB.", exc_info=True)
        
    def username_exist(self, username : str) -> bool:
        '''
        Checks if the username exists in the sql table
        '''
        try:
            self.c.execute("SELECT 1 FROM users WHERE username = ? LIMIT 1", (username,))
            # fetchone() and not fetchall() since:
            # 1. In case no username found fetchone returns None while all() return []
            # 2. In case username found, fetchone returns ('username', ) while fetchall retruns [(username, )] as a tuple.
            # we only need to know IF a username exists and it's value. Therefore, fetchone
            # is more suitable for this case. 
            return self.c.fetchone() is not None 
        
        except Exception as e:
            db_logger.error(f"Falied to check if {username} exists: {e}", exc_info=True)
            return False

    def check_psssword(self, username : str, password : str) -> bool:
        """
        Checks if the password is correct.
        """
        try:
            # fetch password
            self.c.execute("SELECT password,salt FROM users WHERE username = ? LIMIT 1", (username,))
            resp = self.c.fetchone()

            if resp is None:
                return False

            hashed_password, salt = resp
            return PassswordHasher.is_correct_password(salt, password, hashed_password)
        
        except Exception as e:
            db_logger.error(f"Falied to check {username}'s password: {e}", exc_info=True)
            return False

    def delete_user(self, username : str) -> bool:
        try:
            self.c.execute("DELETE FROM users where username = ?", (username, ))
            self.conn.commit()
            db_logger.info(f"Deleted {username} successfully.")
            return True
        
        except Exception as e:
            db_logger.error(f"Falied to delete {username}: {e}", exc_info=True)
            return False

    def print_table(self):
        '''Prints the table'''
        try:
            self.c.execute("SELECT * FROM users")
            res = self.c.fetchall()
            print("----------USERS TABLE------------")
            for user in res:
                print(user)
                print()
            print("----------END TABLE------------")
        
        except Exception as e:
            db_logger.error(f"Falied printing user's table: {e}", exc_info=True)

    # --- BLACKLIST FUNCTIONS ---

    def get_blacklist(self, username : str) -> dict | None:
        try:
            self.c.execute("SELECT blacklist FROM users WHERE username = ?", (username,))
            blacklist = json.loads(self.c.fetchone()[0])
            if blacklist is None:
                db_logger.warning(f"User '{username}' not found in DB when fetching blacklist. Returning empty.")
                return {}
            
            db_logger.debug(f"CMD: get_blacklist. {username}'s Blacklist fetched: {blacklist}")
            return blacklist
        except Exception as e:
            db_logger.error(f"Failed geting {username}'s blacklist: {e}", exc_info=True)
            return None

    def _set_blacklist(self, username: str, bl : dict):
        try:
            json_bl = json.dumps(bl)
            self.c.execute("UPDATE users SET blacklist = ? WHERE username = ?", (json_bl, username))
            self.conn.commit()
        except Exception:
            raise
  
    def add_host_to_blacklist(self, username :str, blacklisted_host: str, details: str) -> bool:
        try:
            bl = self.get_blacklist(username)
            bl[blacklisted_host] = details # if host already in there -> update reason, else adds new key and value to the dict
            self._set_blacklist(username, bl)
            return True
        except Exception as e:
            print(f"[DB] Failed updating/adding host to blacklist of a user: {e}")
            return False

    def delete_host_from_blacklist(self, username : str, to_delete_host : str) -> bool:
        try:
            bl = self.get_blacklist(username)
            bl.pop(to_delete_host)
            self._set_blacklist(username, bl)
            return True
        except KeyError as e:
            print(f"[DB] Failed deleting host, since it doesnt exist in the the DB: {e}")
            return True # allegedly removed
        except Exception as e:
            print(f"[DB] Failed deleting host: {e}")
            return False

    def delete_blacklist(self, username: str) -> bool:
        try:
            self._set_blacklist(username, {})
            return True
        except Exception as e:
            print(f"[DB] Failed deleting blacklist: {e}")
            return False     
        
    # --- TLS TERMINATE FUNCTIONS ---

    def set_tls_terminate(self, username: str, tls_terminate : bool = False) -> bool:
        try:
            int_value = int(tls_terminate)
            self.c.execute("UPDATE users SET tls_terminate = ? WHERE username = ?", (int_value, username))
            self.conn.commit()
            db_logger.info(f"Successfully set {username}'s tls terminate to {int_value}.")
            return True
        except Exception as e:
            db_logger.error(f"Failed setting {username}'s tls_terminate value to {tls_terminate}: {e}", exc_info=True)
            return False        

    def get_tls_terminate(self, username: str) -> bool | None:
        """
        
        :param username: the usernmae's tls_terminate value to check
        :type username: str

        :return: bool (the tls_terminate value) if operation successful AND tls_terminate is an integer, otherwise None.
        :rtype: bool | None

        """
        try:
            self.c.execute("SELECT tls_terminate FROM users WHERE username = ? LIMIT 1", (username, ))
            tls_terminate_tuple = self.c.fetchone()
            if not tls_terminate_tuple:
                return None
            tls_terminate = bool(tls_terminate_tuple[0])
            db_logger.info(f"Successfully fetched {username}'s is_terminate value: {tls_terminate}.")
            return tls_terminate
        except Exception as e:
            db_logger.error(f"Failed fetching {username}'s is_terminate value: {e}", exc_info=True)
            return None

    # --- GOOGLE REDIRECT FUNCTIONS ---

    def set_google_redirect(self, username: str, google_redirect : bool = True) -> bool:
        try:
            int_value = int(google_redirect)
            self.c.execute("UPDATE users SET google_redirect = ? WHERE username = ?", (int_value, username))
            self.conn.commit()
            db_logger.info(f"Successfully set {username}'s google_redirect to {int_value}.")
            return True
        except Exception as e:
            db_logger.error(f"Failed setting {username}'s google_redirect value to {google_redirect}: {e}", exc_info=True)
            return False

    def get_google_redirect(self, username: str, ) -> bool | None:
        """
        
        :param username: the usernmae's google_redirect value to check
        :type username: str

        :return: bool (the google_redirect value) if operation successful AND google_redirect is an integer, otherwise None.
        :rtype: bool | None

        """
        try:
            self.c.execute("SELECT google_redirect FROM users WHERE username = ? LIMIT 1", (username, ))
            google_redirect_tuple = self.c.fetchone()
            if not google_redirect_tuple:
                return None
            google_redirect = bool(google_redirect_tuple[0])
            db_logger.info(f"Successfully fetched {username}' google_redirect value: {google_redirect}.")
            return google_redirect
        except Exception as e:
            db_logger.error(f"Failed fetching {username}'s google_redirect value: {e}", exc_info=True)
            return None

if __name__ == "__main__":

    # db= SQLAuthManager()
    # db.delete_user("HelloThere")
    # db.delete_user("jo")
    # db.delete_user("bro")
    # db.delete_user("krik")

    # db.save_user("HelloThere", "1q2w3e")
    # db.save_user("jo", "1q2w3e")
    # db.save_user("bro", "aaaaa")
    # db.save_user("krik", "1qw2e3e3r")
    # # db.save_user("HelloThere", "Noedkf")
    # db.print_table()
    # print(db.username_exist("HelloThere"))
    # db.check_psssword("jo" ,"1q2w3e")
    # db.delete_user("HelloThere")
    # db.print_table()

    # test blacklist funcs
    db= SQLAuthManager()
    db.delete_user("aaaaa")
    db.print_table()
    db.save_user("aaaaa", "aaaaa")
    db.add_or_update_host_to_blacklist("aaaaa", "www.co.il", "Inappropriate")
    db.add_or_update_host_to_blacklist("aaaaa", "www.com", "Inappropriate")
    db.print_table()
    db.add_or_update_host_to_blacklist("aaaaa", "www.com", "xxx")
    db.print_table()
    db.delete_host_from_blacklist("aaaaa", "www.co.il")
    db.print_table()
    db.delete_blacklist("aaaaa")
    db.print_table()
