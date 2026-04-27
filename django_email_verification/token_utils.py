from datetime import datetime

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model

class EmailVerificationTokenGenerator:
    """
    Strategy object used to generate and check tokens for the password
    reset mechanism.
    """
    try:
        key_salt = settings.CUSTOM_SALT
    except AttributeError:
        key_salt = "django-email-verification.token"
    algorithm = None
    secret = settings.SECRET_KEY

    def make_token(self, user, expiry, **kwargs):
        """
        Return a token that can be used once to do a password reset
        for the given user.

        Args:
            user (Model): the user
            expiry (datetime | int): optional forced expiry date
            kwargs: extra payload for the token

        Returns:
             (tuple): tuple containing:
                token (str): the token
                expiry (datetime): the expiry datetime
        """
        exp = int(expiry.timestamp()) if isinstance(expiry, datetime) else expiry
        payload = {'email': user.email, 'exp': exp}
        payload.update(**kwargs)
        return jwt.encode(payload, self.secret, algorithm='HS256'), datetime.fromtimestamp(exp)

    def check_token(self, token, **kwargs):
        """
        Check that a password reset token is correct.
        Args:
            token (str): the token from the url
            kwargs: the extra required payload

        Returns:
            (tuple): tuple containing:
                valid (bool): True if the token is valid
                user (Model): the user model if the token is valid
        """

        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256']) #автоматическая проверка на то, что токен не истёк
            email, exp = payload['email'], payload['exp']

            for k, v in kwargs.items():
                if payload[k] != v:
                    return False, None

            if hasattr(settings, 'EMAIL_MULTI_USER') and settings.EMAIL_MULTI_USER:
                users = get_user_model().objects.filter(email=email) 
            else:
                users = [get_user_model().objects.get(email=email)]
        except (ValueError, get_user_model().DoesNotExist, jwt.DecodeError, jwt.ExpiredSignatureError):
            return False, None

        if not len(users) or users[0] is None:
            return False, None

        return True, users[0]
    
    def check_token_update_email(self, token, **kwargs):
        """      
        Check that a password reset token is correct.
        Args:
            token (str): the token from the url
            kwargs: the extra required payload

        Returns:
            (tuple): tuple containing:
                valid (bool): True if the token is valid
                user (Model): the user model if the token is valid
                new_email (str): the new user email
        """
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            old_email, new_email, exp = payload['email'], payload['new_email'], payload['exp']
            
            if not new_email:
                return False, None, None

            for k, v in kwargs.items():
                if payload[k] != v:
                    return False, None, None

            try:
                user = get_user_model().objects.get(email=old_email)
            except get_user_model().DoesNotExist:
                return False, None, None

        except (ValueError, jwt.DecodeError, jwt.ExpiredSignatureError):
            return False, None, None

        return True, user, new_email
    
    @staticmethod
    def now():
        return datetime.now().timestamp()


default_token_generator = EmailVerificationTokenGenerator()
