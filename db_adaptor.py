from pymysql import connect, cursors, Error
from credentials_validator import *


class DatabaseAdapter:
    """
    Class is responsible to establish connection to the specific MySQL database,
    according to the passed connection credentials
    """

    def __init__(self, host: str, db_name: str, username: str, password: str):
        """
        Constructor to assign DatabaseAdapter connection credentials
        :param host: Host name to connect to
        :param db_name: Database to work with
        :param username: Username to connect the database with
        :param password: Password to connect the database with
        :raises AttributeError if  at least one of the given connection credentials is invalid
        """
        self.connection = None

        self.host = host
        self.db_name = db_name
        self.username = username
        self.password = password

    # Getters
    @property
    def connection(self):
        """
        Getter returns the connection object reference
        :return: The connection object reference
        """
        return self.__connection

    @property
    def host(self) -> str:
        """
        Getter returns the host ip/name
        :return: Host ip/name
        """
        return self.__host

    @property
    def db_name(self) -> str:
        """
        Getter returns the database name
        :return: Database name
        """
        return self.__db_name

    @property
    def username(self) -> str:
        """
        Getter returns a username to connect the database with
        :return: A username to connect the database with
        """
        return self.__username

    @property
    def password(self) -> str:
        """
        Getter returns a password to connect the database with
        :return: A password to connect the database with
        """
        return self.__password

    # Setters
    @host.setter
    def host(self, host: str) -> None:
        """
        Setter sets a host to connect to
        :param host: A host to connect to
        :raises AttributeError - If the given host ip address is not valid and is not "localhost"
        :return: None
        """
        if host != "localhost" and not CredentialsValidator.validate_ipv4(host):
            raise AttributeError("Error. Wrong host ip is given. Only host ip address to connect to is allowed")

        self.__host = host

    @db_name.setter
    def db_name(self, db_name: str) -> None:
        """
        Setter sets a name of the database to connect to
        :param db_name: A name of the databases to connect to
        :raises AttributeError - if the given database name format is invalid
        :return: None
        """
        if not CredentialsValidator.validate_database_name(db_name):
            raise AttributeError("Wrong database name")

        self.__db_name = db_name

    @username.setter
    def username(self, username: str) -> None:
        """
        Setter sets a username to connect the database with
        :param username: A username to connect the database with
        :raises AttributeError - if the given username's format is not valid
        :return: None
        """
        if not CredentialsValidator.validate_username(username):
            raise AttributeError("Username can contain letters and _ only")

        self.__username = username

    @password.setter
    def password(self, password: str) -> None:
        """
        Setter sets a password to connect the database with
        :param password: A password to connect the database with
        :raises AttributeError - if the given password's format is not valid
        :return: None
        """
        if type(password) is not str:  # Changed from isinstance() to type() for string check
            raise AttributeError("Password must be a string")

        self.__password = password

    @connection.setter
    def connection(self, connection) -> None:
        """
        Setter sets a connection object reference
        :param connection: A connection object reference
        :return: None
        """
        self.__connection = connection

    # Database Connect/disconnect methods
    def connect(self) -> None:
        """
        Method is responsible to connect to the database
        :raises RuntimeError - If the database connection couldn't be established for any reason
        :return: None
        """
        try:
            if self.connection is None:
                self.connection = connect(
                    host=self.host,
                    user=self.username,
                    password=self.password,
                    db=self.db_name,
                    cursorclass=cursors.DictCursor
                )
        except Error as e:
            raise RuntimeError(f"Database connection couldn't be established. Error pymysql {e}")

    def disconnect(self) -> None:
        """
        Method is responsible to close an opened database connection
        :raises RuntimeError - If the database connection couldn't be closed for any reason
        :return: None
        """
        try:
            if self.connection is not None:
                self.connection.cursor().close()
                self.connection.close()
                self.connection = None  # Setting the connection reference to None
        except Error as e:
            raise RuntimeError(f"Could not close connection error pymysql {e}")
