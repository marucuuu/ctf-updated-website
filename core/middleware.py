from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from core.models import UserProfile
import re

class AuthTemporaryPasswordAndVerificationMiddleware(MiddlewareMixin):
    """
    Middleware to:
    1. Redirect unauthenticated users to the login view.
    2. Redirect authenticated users who must change their temporary password.
    3. Redirect authenticated but unverified users to the verification view.
    """
    def process_request(self, request):
        # Allow access to specific views for unauthenticated or unverified users
        allowed_urls = [
            reverse('login'),  # Login view
            reverse('logout'),  # Logout view
            reverse('change_password_temporary'),  # Temporary password change view
            reverse('verify'),  # Account verification view
            reverse('forgot_password'),  # Forgot password view
            reverse('setup'),
            reverse('register'),
        ]

        # Allow reset password URLs dynamically
        reset_password_pattern = re.compile(r'^/reset/(?P<uidb64>[^/]+)/(?P<token>[^/]+)/$')

        # Check if the user is authenticated
        if not request.user.is_authenticated:
            # Allow unauthenticated users to access the allowed URLs and reset password URLs
            if request.path not in allowed_urls and not reset_password_pattern.match(request.path):
                return redirect('login')  # Redirect unauthenticated users to the login view
            return None

        # Check if the user has a profile
        try:
            user_profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            return None

        # Check if the user must change their temporary password
        if user_profile.must_change_password and request.path not in allowed_urls:
            return redirect('change_password_temporary')  # Redirect to temporary password change

        # Check if the user is verified
        if not user_profile.verified and request.path not in allowed_urls:
            return redirect('verify')  # Redirect to verification page if unverified

        return None