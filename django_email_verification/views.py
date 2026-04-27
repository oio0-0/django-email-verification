from django.conf import settings
from django.core.handlers.wsgi import WSGIRequest
from django.shortcuts import render
from django.contrib.auth import login

from .confirm import verify_email_view, verify_email, verify_password_view, verify_password, verify_email_update
from .errors import NotAllFieldCompiled

@verify_email_view
def verify_email_page(request: WSGIRequest, token):
    try:
        template = settings.EMAIL_MAIL_PAGE_TEMPLATE
        success, user = verify_email(token)
        user.save()

        if success and user is not None:
            login(request, user)
        
        return render(request, template, {'success': success, 'user': user, 'request': request})
    except (AttributeError, TypeError):
        raise NotAllFieldCompiled('EMAIL_MAIL_PAGE_TEMPLATE field not found')

@verify_password_view
def verify_password_page(request: WSGIRequest, token):
    try:
        if request.method == 'POST' and (pwd := request.POST.get('password')) is not None:
            success, user = verify_password(token, pwd)
            return render(request, settings.EMAIL_PASSWORD_PAGE_TEMPLATE,
                          {'success': success, 'user': user, 'request': request})
        return render(request, settings.EMAIL_PASSWORD_CHANGE_PAGE_TEMPLATE, {'token': token, 'request': request})
    except (AttributeError, TypeError):
        raise NotAllFieldCompiled('EMAIL_PASSWORD templates field not found')

@verify_email_update_view
def verify_email_update_page(request: WSGIRequest, token):
    try:
        template = settings.EMAIL_MAIL_UPDATE_PAGE_TEMPLATE
        success, user, new_email = verify_email_update(token)
        user.email = new_email
        user.save()

        if success and user is not None:
            login(request, user)
        
        return render(request, template, {'success': success, 'user': user, 'request': request})
    except (AttributeError, TypeError):
        raise NotAllFieldCompiled('EMAIL_MAIL_UPDATE_PAGE_TEMPLATE field not found')
