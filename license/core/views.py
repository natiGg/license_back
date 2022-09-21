from django.shortcuts import render

# Create your views here.
from asyncio.windows_events import NULL
from email.mime import image
from django.http import request
from django.shortcuts import render
import random
import string
import json
# Create your views here.
from django.shortcuts import render
from rest_framework import serializers, status
from rest_framework import generics
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.generics import CreateAPIView,GenericAPIView,RetrieveUpdateDestroyAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import views
from core.serializers import EmailVerificationSerializer,EmailCheckSerializer,UnameSuggestSerializer,UnameCheckSerializer,LoginSerializer,PasswordResetEmailSerializer,ChangePwdSerializer,UserAvatarSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import School, Student, User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from .renderers import UserRenderer
from django.utils.encoding import smart_str,force_str,smart_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.shortcuts import redirect
# Create your views here.
from django.http import HttpResponsePermanentRedirect
import os
from rest_framework.parsers import MultiPartParser, FormParser

from django.shortcuts import render
from rest_framework import serializers
from rest_framework.generics import ListCreateAPIView,RetrieveUpdateDestroyAPIView
from .serializers import  SchoolSerializer, StudentSerializer,UpdateStudentProfileSerializer,UpdateSchoolProfileSerializer
from rest_framework import permissions
from .permissions import IsPostedBy


class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'tel','http', 'https','laugh1','com.example.laugh1']

class SchoolRegistrationView(GenericAPIView):
    serializer_class = SchoolSerializer
    renderer_classes =(UserRenderer,)
    def post(self, request):
        user = request.data
        print(user)
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user=User.objects.get(email=user_data["email"])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink=reverse('email-verify')
        redirect_url=request.data.get("redirect_url","")
        abs_url='http://'+current_site+relativeLink+"?token="+str(token)
        email_body='Hi '+user.username+' use the link below \n to verify your email \n'+ abs_url #+"?redirect_url="+redirect_url
        print(abs_url)
        data={'to_email':user.email,'email_body':email_body,'email_subject':'verify your email'}
        try:
            Util.send_email(data)
        except Exception as e:
            return Response(user_data, status=status.HTTP_403_FORBIDDEN)

        staus_code = status.HTTP_201_CREATED
        return Response(user_data, status=staus_code)

class StudentRegistrationView(GenericAPIView):
    serializer_class = StudentSerializer
    renderer_classes =(UserRenderer,)
    def post(self, request):
        user = request.data
        print(user)
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user=User.objects.get(email=user_data["email"])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink=reverse('email-verify')
        redirect_url=request.data.get("redirect_url","")
        abs_url='http://'+current_site+relativeLink+"?token="+str(token)
        email_body='Hi '+user.username+' use the link below \n to verify your email \n'+ abs_url #+"?redirect_url="+redirect_url
        print(abs_url)
        data={'to_email':user.email,'email_body':email_body,'email_subject':'verify your email'}
        try:
            Util.send_email(data)
        except Exception as e:
            return Response(user_data, status=status.HTTP_403_FORBIDDEN)

        staus_code = status.HTTP_201_CREATED
        return Response(user_data, status=staus_code)

class UpdateSchoolProfileView(views.APIView):
    serializer_class = UpdateSchoolProfileSerializer
    parser_classes = [MultiPartParser, FormParser]
    renderer_classes =(UserRenderer,)
    def post(self,request):
        userprofile = request.data
        user= request.data.get('user')
        instance=School.objects.get(user=user)
        serializer = self.serializer_class(instance,data=userprofile)    
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data       
        return Response(user_data,status=status.HTTP_200_OK)

class UpdateStudentProfileView(views.APIView):
    serializer_class = UpdateSchoolProfileSerializer
    parser_classes = [MultiPartParser, FormParser]
    renderer_classes =(UserRenderer,)
    def post(self,request):
        userprofile = request.data
        user= request.data.get('user')
        instance=Student.objects.get(user=user)
        serializer = self.serializer_class(instance,data=userprofile)    
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data       
        return Response(user_data,status=status.HTTP_200_OK)


class SchoolAvatarUpload(views.APIView):
    parser_classes = [MultiPartParser, FormParser]
    renderer_classes =(UserRenderer,)

    def post(self, request, format=None):
        user=request.data.get('user')
        instance=School.objects.get(user=user)
        serializer = UserAvatarSerializer(data=request.data, instance=instance)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  

class StudentAvatarUpload(views.APIView):
    parser_classes = [MultiPartParser, FormParser]
    renderer_classes =(UserRenderer,)

    def post(self, request, format=None):
        user=request.data.get('user')
        instance=Student.objects.get(user=user)
        serializer = UserAvatarSerializer(data=request.data, instance=instance)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  

class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        redirect_url = request.GET.get('redirect_url')
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token,settings.SECRET_KEY,algorithms=["HS256"]) 
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            # return CustomRedirect(redirect_url+"?email=Activated")
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'email': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
            # return CustomRedirect(redirect_url+"?email=Activation Expired")
        except jwt.exceptions.DecodeError as identifier:
            return Response({'email': 'Activation Expired'}, status=status.HTTP_401_UNAUTHORIZED)
            # return CustomRedirect(redirect_url+"?error=Invalid token")

class LoginAPIView(generics.GenericAPIView):
    serializer_class=LoginSerializer
    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

class PasswordResetEmail(generics.GenericAPIView):
    serializer_class =PasswordResetEmailSerializer
    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        email=request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 =urlsafe_base64_encode(smart_bytes(user.id))
            token=PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink=reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
            redirect_url=request.data.get("redirect_url","")
            abs_url='http://'+current_site+relativeLink
            email_body='Hello, use the link below \n to reset your password \n'+ abs_url+"?redirect_url="+redirect_url
            print(abs_url)
            data={'to_email':user.email,'email_body':email_body,'email_subject':'Reset Password'}
            Util.send_email(data)
            return Response({'success':'We have sent you a link to reset your password'},status=status.HTTP_200_OK)
        else:
             return Response({'error':'email does not exist'},status=status.HTTP_404_NOT_FOUND)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class=ChangePwdSerializer
    def get(self, request, uidb64, token):
        redirect_url = request.GET.get('redirect_url')
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')
            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return CustomRedirect(os.environ.get('FRONTEND_URL', '')+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return CustomRedirect(redirect_url+'?token_valid=False')
                    
            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)



class ChangePwdAPIView(generics.GenericAPIView):
    serializer_class=ChangePwdSerializer

    def patch(self,request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success':True,'message':'Password Reset success'},status=status.HTTP_200_OK)

class EmailChecker(generics.GenericAPIView):
    serializer_class =EmailCheckSerializer
    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        email=request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            return Response({'error':'email already exists'},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'success':'email can be used'},status=status.HTTP_200_OK)

class UnameChecker(generics.GenericAPIView):
    serializer_class =UnameCheckSerializer
    def post(self,request):
        uname=request.data['username']
        if User.objects.filter(username=uname).exists():
            return Response({'error':'username already exists'},status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({'success':'username can be used'},status=status.HTTP_200_OK)


class UnameSuggest(generics.GenericAPIView):
    serializer_class = UnameSuggestSerializer
    renderer_classes =(UserRenderer,)

    def post(self,request):
        suggestions=[]
        try:
            uname=request.data['username']
            staus_code = status.HTTP_201_CREATED

            if User.objects.filter(username=uname).exists():
                for i in range(1,8):
                    suggestions.append(uname+str(random.choice(string.ascii_letters))+random.choice(string.ascii_letters))
                return Response(suggestions,status=staus_code)
            else:
                for i in range(1,8):
                    suggestions.append(uname+str(random.choice(string.ascii_letters))+random.choice(string.ascii_letters))
                return Response(suggestions,status=status.HTTP_200_OK)
        except Exception as e:
                return Response(suggestions,status=status.HTTP_200_OK)


# Create your views here.
class SchoolsFetch(ListCreateAPIView):
    serializer_class = SchoolSerializer
    queryset = School.objects.all()
    # permission_classes = (permissions.IsAuthenticated,)

    def perform_create(self, serializer):
        return serializer.save(posted_by=self.request.user)

    def get_queryset(self):
        return self.queryset.all()

