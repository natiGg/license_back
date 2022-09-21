import email
from statistics import mode
from turtle import title
from unicodedata import name
import uuid
from django.db import models

from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser,PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self,username,email,password=None):

        if not email:
            raise TypeError('Must have an email')
        
        if not username:
            raise TypeError('Must have an username')

        user = self.model(username=username,
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self,username,email,password):
        if password is None:
            raise TypeError('SuperUsers must have a pwd')
        
        if email is None:
            raise TypeError('SuperUsers should have a email')
      
        user=self.create_user(username,email,password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user

class User(AbstractBaseUser,PermissionsMixin):
    username=models.CharField(max_length=255,unique=True,db_index=True)
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
        db_index=True
        )
    is_using_google=models.BooleanField(default=True)
    password=models.CharField(null=True,max_length=200)
    is_school = models.BooleanField(default=False)
    is_student= models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified=models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    def __str__(self):
        return self.email
    objects = UserManager()
    def __str__(self):
        return self.email
        
    def tokens(self):
        refresh=RefreshToken.for_user(self)
        return {
            'refresh':str(refresh),
            'access':str(refresh.access_token)
        }
    class Meta:
        '''
        to set table name in database
        '''
        db_table = "users"


class School(models.Model):
    id = models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False,blank=False)
    school=models.OneToOneField(User,on_delete=models.CASCADE, related_name='school_user')
    name=models.CharField(max_length=200)
    phone_num=models.IntegerField()
    address=models.TextField()
    profile_pic = models.ImageField(null=True,blank=True,upload_to="student_profiles/")
    def __str__(self):
        return self.name
    class Meta:
        '''
        to set table name in database
        '''
        db_table = "School"


class License(models.Model):
    license_id = models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False,blank=False)
    license_type=models.TextField()
    def __str__(self):
        return self.license_type


class Course(models.Model):
    id= models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False,blank=False)
    school_id=models.ForeignKey(School,on_delete=models.CASCADE, related_name='course_school_user')
    license_id=models.ForeignKey(License,on_delete=models.CASCADE, related_name='course_license_type')
    title=models.CharField(max_length=500)
    description=models.TextField()
    def __str__(self):
        return self.title
    

class Student(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='student',unique=True)
    school_id=models.OneToOneField(School,on_delete=models.CASCADE, related_name='school_user',unique=True)
    name=models.CharField(max_length=500)
    age=models.IntegerField()
    profile_pic = models.ImageField(null=True,blank=True,upload_to="school_profiles/")
    phone_number=models.TextField()
    def __str__(self):
        return self.name
    class Meta:
        '''
        to set table name in database
        '''
        db_table = "Student"

class Question(models.Model):
    id= models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False,blank=False)
    school_id=models.OneToOneField(School,on_delete=models.CASCADE, related_name='questions_school',unique=True)
    license_id=models.ForeignKey(License,on_delete=models.CASCADE, related_name='question_license_type')
    is_image_type=models.BooleanField(default=False)
    question_text = models.TextField(max_length=200,default="")
    def __str__(self):
        return self.question_text

class Option(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    option = models.TextField(default="")
    is_correct_option=models.BooleanField(default=False)
    def __str__(self):
        return self.option

class Answer(models.Model):
    question = models.OneToOneField(
        Question,
        on_delete=models.CASCADE,
        primary_key=True,
    )
    answer = models.ForeignKey(
        Option,
        on_delete=models.CASCADE,
      
    )
    def __str__(self):
        return self.answer.option
