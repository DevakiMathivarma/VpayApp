from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()
class CustomSocialAdapter(DefaultSocialAccountAdapter):

    def get_login_redirect_url(self, request):
        user = request.user

        # If user has NOT completed KYC
        if not hasattr(user, "testkyc"):     # update based on your model
            return "/test_view/"

        # If KYC completed
        return "/vpay_dashboard/"
    
    def pre_social_login(self, request, sociallogin):
        """
        Link Google account to existing user by email
        """
        email = sociallogin.account.extra_data.get("email")

        if not email:
            return

        try:
            user = User.objects.get(email=email)
            sociallogin.connect(request, user)
        except User.DoesNotExist:
            pass
