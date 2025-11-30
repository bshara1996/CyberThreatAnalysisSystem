from db_adaptor import *  # Assuming `DatabaseAdapter` is defined here


class QueryHandler(DatabaseAdapter):
    def __init__(self, host: str, db_name: str, username: str, password: str):
        """
        Constructor to assign DatabaseAdapter connection credentials
        :param host: Host name to connect to
        :param db_name: Database to work with
        :param username: Username to connect the database with
        :param password: Password to connect the database with
        :raises ValueError if one of the given connection credentials is at least invalid
        """
        super().__init__(host, db_name, username, password)

    def execute_fetch(self, query: str, conditions: tuple) -> list:
        """
        Method executes a fetch query that is passed to the current method
        :param query: Fetch Query to execute
        :param conditions: Conditions to execute the query with
        :raises RuntimeError - when there was a problem working with the database or passed arguments are invalid
        :return: List that contains the list with returned records
        """
        # Checking if the arguments are valid
        if type(query) is not str or type(conditions) is not tuple:
            raise ValueError("At least one of the arguments that is passed to execution query method is invalid")

        try:
            self.connect()

            # As long as there are some records to pass
            with self.connection.cursor() as cursor:
                # Query to execute
                cursor.execute(query, conditions)

                fetch_records = cursor.fetchall()  # Saving a list of dictionaries where each dictionary is a record

                return fetch_records

        except RuntimeError as e:
            raise RuntimeError(f"Error during fetch operation: {e}")

        finally:
            self.disconnect()

    def execute_non_fetch(self, query: str, conditions: tuple) -> None:
        """
        Method executes a non-fetch query that is passed to the current method
        :param query: Non-fetch Query to execute
        :param conditions: Conditions to execute the query with
        :raises RuntimeError - when there was a problem working with the database or passed arguments are invalid
        :return: None
        """
        # Checking if the arguments are valid
        if type(query) is not str or type(conditions) is not tuple:
            raise ValueError("At least one of the arguments that is passed to execution query method is invalid")

        try:
            self.connect()

            # Execute non-fetch query
            self.connection.cursor().execute(query, conditions)
            self.connection.commit()  # Saving the result (without the commit, results won't be saved to the database)

        except RuntimeError as e:
            raise RuntimeError(f"Error during non-fetch operation: {e}")

        finally:
            self.disconnect()
