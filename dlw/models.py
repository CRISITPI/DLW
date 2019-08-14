from django.db import models

# Create your models here.

class testc(models.Model):
    subject=models.CharField(null=True,max_length=20)
    targetone=models.IntegerField(null=True)
    targettwo=models.IntegerField(null=True)

class navbar(models.Model):
    role=models.CharField(null=True,max_length=50)
    navmenu=models.CharField(null=True,max_length=50)
    navitem=models.CharField(null=True,max_length=50)
    navsubitem=models.CharField(null=True,max_length=50)
    link=models.CharField(null=True,max_length=50)


class user_master(models.Model):
    emp_id=models.CharField(max_length=15,primary_key=True)
    role=models.CharField(max_length=500,null=True)
    parent=models.CharField(max_length=50,null=True)
    name=models.CharField(max_length=50,null=True)
    designation=models.CharField(max_length=50,null=True)
    department=models.CharField(max_length=50,null=True)
    email=models.CharField(max_length=50,null=True)
    contactno=models.CharField(null=True,max_length=10)

class roles(models.Model):
    role=models.CharField(primary_key=True,max_length=50)
    parent=models.CharField(max_length=50,null=True)

