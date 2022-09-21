from rest_framework import permissions


class IsPostedBy(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.posted_by == request.user