from unicodedata import name
from core.views import EmailChecker,UnameChecker,ChangePwdAPIView, PasswordTokenCheckAPI,PasswordResetEmail,UnameSuggest,SchoolsFetch
from core.views import VerifyEmail
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from core.views import LoginAPIView,SchoolRegistrationView,StudentRegistrationView,SchoolsFetch, SchoolAvatarUpload, StudentAvatarUpload,AddLicense, UpdateSchoolProfileView, UpdateStudentProfileView

urlpatterns = [
    path('',SchoolsFetch.as_view(),name="SchoolsList"),
    path('register_school/',SchoolRegistrationView.as_view(),name="school_register"),
    path('register_student/',StudentRegistrationView.as_view(),name="student_register"),
    path('add_license/',AddLicense.as_view(),name="student_register"),
    path('login/',LoginAPIView.as_view(),name="login"),
    path('school_update/',UpdateSchoolProfileView.as_view(),name="update"),
    path('student_update/',UpdateStudentProfileView.as_view(),name="update"),
    path('fetch_schools',SchoolsFetch.as_view(),name="schools_list"),
    path('email-verify/',VerifyEmail.as_view(),name="email-verify"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-password',PasswordResetEmail.as_view(),name="request-reset-password"),
    path('password-reset/<uidb64>/<token>/',PasswordTokenCheckAPI.as_view(),name='password-reset-confirm'),
    path('password-reset-complete',ChangePwdAPIView.as_view(),name='password-reset-complete'),
    path('email-checker/',EmailChecker.as_view(),name="email-chekcer"),
    path('uname-checker/',UnameChecker.as_view(),name="uname-chekcer"),
    path('uname-suggest/',UnameSuggest.as_view(),name="uname-chekcer"),
    path('school_avatar-upload/',SchoolAvatarUpload.as_view(),name="school_avatar-upload"),
    path('user_avatar-upload/',StudentAvatarUpload.as_view(),name="student_avatar-upload"),
]
