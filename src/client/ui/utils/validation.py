import flet as ft


class AuthValidatior:

    @staticmethod
    def _validate_fields_length(u : str, p : str, user_input: str, pw_input: str) -> bool:
        """
        :param u: username
        :param p: password
        :return: True if the length of data is valid, otherwise False.
        """
        valid = True
        if len(u) < 3:
            user_input.error_text = "Must be minimum 3 chars"
            valid = False
        elif len(u) > 30:
            user_input.error_text = "Must be maximum 30 chars" 
            valid = False

        if len(p) < 5:
            pw_input.error_text = "Must be minimum 5 chars"
            valid = False
        if len(p) > 30:
            pw_input.error_text = "Must be maximum 30 chars"
            valid = False
        return valid