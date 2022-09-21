from django.contrib import admin

from core.models import User,School,License,Course,Student,Question,Option,Answer


# Register your models here.
admin.site.register(User)
admin.site.register(School)
admin.site.register(License)
admin.site.register(Course)
admin.site.register(Student)
admin.site.register(Question)
admin.site.register(Option)
admin.site.register(Answer)

