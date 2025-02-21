import random
import datetime
from django.utils import timezone
from django.contrib.auth.tokens import default_token_generator

class ExpiringTokenGenerator(default_token_generator.__class__):
    def __init__(self, token_lifetime=2):
        super().__init__()
        self.token_lifetime = token_lifetime  # Lifetime in minutes

    def make_token(self, user):
        # Generate a 6-digit numeric code
        code = f'{random.randint(100000, 999999)}'
        timestamp = int(timezone.now().timestamp())
        return f'{code}:{timestamp}'

    def check_token(self, user, token):
        try:
            code, timestamp = token.split(':', 1)
            timestamp = int(timestamp)
            token_time = datetime.datetime.fromtimestamp(timestamp, tz=timezone.get_current_timezone())
            if timezone.now() > token_time + datetime.timedelta(minutes=self.token_lifetime):
                return False
            # Check if the code is exactly 6 digits long
            return code.isdigit() and len(code) == 6
        except ValueError:
            return False

# Create an instance with the desired expiration time
expiring_token_generator = ExpiringTokenGenerator(token_lifetime=2)  # 2 minutes
