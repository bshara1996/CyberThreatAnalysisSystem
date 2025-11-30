from ipaddress import ip_address
from re import match
from abc import ABC


class CredentialsValidator(ABC):
    """
    Utility class that contains methods that check the database connection credentials
    """

    # Checking the ipv4 for host
    @staticmethod
    def validate_ipv4(ipv4_to_check: str) -> bool:
        """
        Utility method that validates a given ipv4 address
        :param ipv4_to_check: IPv4 to validate
        :raises ValueError if the given ip is not a valid version4 address
        :return: True if the given value is a valid ip address and False otherwise
        """
        try:
            # checking the ipv4 address format octet.octet.octet.octet
            if not CredentialsValidator.validate_ipv4_format(ipv4_to_check):
                return False

            # Will return an exception if the current ipv4 is not valid
            ip_address(ipv4_to_check)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_ipv4_format(ipv4_to_check: str) -> bool:
        """
        Method validates if the given ipv4 address is a string and its format is valid
        :param ipv4_to_check: IPv4 to validate
        :return:
        """
        return type(ipv4_to_check) is str and match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ipv4_to_check)

    # Checking the database name
    @staticmethod
    def validate_database_name(db_name_to_check: str) -> bool:
        """
        Method validates a database name
        :param db_name_to_check: A database name to check
        :return: True if the given value is a valid database name and False otherwise
        """
        return type(db_name_to_check) is str and match(r"^[0-9a-zA-Z$_]+$", db_name_to_check)

    # Checking the username
    @staticmethod
    def validate_username(username_to_check: str) -> bool:
        """
        Method validates the database connection username
        :param username_to_check: Username to check
        :return: True if the given value is a valid username and False otherwise
        """
        return type(username_to_check) is str and match(r"^[a-zA-Z_]+$", username_to_check)
