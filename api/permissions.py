from rest_framework import permissions
from django.conf import settings


class MobileAccessPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        return request.user.status == "1"


class AuthorityPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        return bool(request.user.user_type == "2")


class WebhookAccessPermission(permissions.BasePermission):

    def has_permission(self, request, view):
        try:
            x_api_key = request.headers['X-API-KEY']
            if x_api_key == str(settings.ACCESS_KEY):
                return True

        except Exception as e:
            return False
