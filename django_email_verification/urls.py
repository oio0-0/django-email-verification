from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .views import verify_email_page, verify_password_page, verify_email_update_page

urlpatterns = [
    path('email-update/<str:token>', csrf_exempt(verify_email_update_page)),
    path('email/<str:token>', csrf_exempt(verify_email_page)),
    path('password/<str:token>', csrf_exempt(verify_password_page)),
]
