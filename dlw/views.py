from django.shortcuts import render,redirect
from django.http import HttpResponse,JsonResponse,HttpResponseRedirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from datetime import date,datetime,timedelta
import datetime
from django.contrib.sessions.models import Session
from rest_framework.views import APIView
from rest_framework.response import Response
from django.views.generic import View
from dlw.models import testc,navbar,user_master,roles
from dlw.serializers import testSerializer
import re,uuid
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import password_reset,password_reset_done
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from dlw.forms import UserRegisterForm
from django.contrib import auth
from authy.api import AuthyApiClient
from django.conf import settings
from django.contrib.auth.decorators import user_passes_test
from dlw.decorators import role_required
# Create your views here.
#
#
#
#
#
#
#
#
#
#
#
def login_request(request):
    if request.method=='POST':
        u_id = request.POST.get('user_id')
        pwd=request.POST.get('password')
        user = authenticate(username=u_id, password=pwd)
        if user is not None:
            login(request, user)
            currentuser=user_master.objects.filter(emp_id=user).first()
            rolelist=roleslist(request,currentuser.role)
            if "Superuser" in rolelist:
                return redirect('homeadmin')
            else:
                return redirect('homeuser')
        else:
            messages.error(request,"Invalid username or password")
    form = AuthenticationForm()
    return render(request, 'login.html', {"form": form})





def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip





@login_required
def logout_request(request):
    if request.method=='POST':
        logout(request)
        data={}
        return JsonResponse(data)
    return HttpResponseRedirect('login')




def roleslist(request,oldstr):
    newstr=oldstr.replace("'","")
    length=len(newstr)
    newstrfin=newstr[1:length-1]
    newlength=len(newstrfin)
    rolelist=newstrfin.split(", ")
    return rolelist




@login_required
@role_required(allowed_roles=["Superuser"])
def homeadmin(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolestring=usermaster.role
    rolelist=roleslist(request,rolestring)
    nav=dynamicnavbar(request,rolelist)
    context={
        'nav':nav,
        'usermaster':usermaster,
        'ip':get_client_ip(request),
    }
    return render(request,'homeadmin.html',context)





@login_required
@role_required(allowed_roles=["Bogie","Wheel"])
def homeuser(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolestring=usermaster.role
    rolelist=roleslist(request,rolestring)
    nav=dynamicnavbar(request,rolelist)
    context={
        'nav':nav,
        'usermaster':usermaster,
        'ip':get_client_ip(request),
    }
    return render(request,'homeuser.html',context)








@login_required
def dynamicnavbar(request,rolelist=[]):
    if("Superuser" in rolelist):
        nav=navbar.objects.filter(role="Superuser")
        return nav
    else:
        nav=navbar.objects.filter(role__in=rolelist).values('navmenu','navitem','navsubitem','link').distinct()
        return nav







@login_required
@role_required(allowed_roles=["Superuser"])
def create(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolestring=usermaster.role
    rolelist=roleslist(request,rolestring)
    nav=dynamicnavbar(request,rolelist)
    emp=user_master.objects.filter(role__isnull=True)
    availableroles=roles.objects.all()
    if request.method == "POST":
        emp_id=request.POST.get('emp_id')
        email=request.POST.get('email')
        role=request.POST.getlist('role')
        password="dlw@123"
        if role=="Superuser" and emp_id and role:
            employee=user_master.objects.filter(emp_id=emp_id).first()
            employee.role=role
            newuser = User.objects.create_user(username=emp_id, password=password,email=email)
            employee.save()
            newuser.is_staff= True
            newuser.is_superuser=True
            newuser.save()
            messages.success(request, 'Successfully Created!')
            return redirect('create')
        elif role!="Superuser" and emp_id and role:
            employee=user_master.objects.filter(emp_id=emp_id).first()
            employee.role=role
            newuser = User.objects.create_user(username=emp_id, password=password,email=email)
            employee.save()
            newuser.is_staff= True
            newuser.is_superuser=False
            newuser.save()
            messages.success(request, 'Successfully Created!')
            return redirect('create')
        else:
            messages.error(request, 'Error, Try Again!')
    context={
        'nav':nav,
        'usermaster':usermaster,
        'emp':emp,
        'ip':get_client_ip(request),
        'roles':availableroles,
    }

    return render(request,'createuser.html',context)







def getEmpInfo(request):
    if request.method == "GET" and request.is_ajax():
        emp_id=request.GET.get('username')
        try:
            emp=user_master.objects.filter(emp_id=emp_id).first()
        except:
            return JsonResponse({"success":False}, status=400)
        emp_info={
            "name":emp.name,
            "designation":emp.designation,
            "department":emp.department,
            "email":emp.email,
            "contactno":emp.contactno
        }
        return JsonResponse({"emp_info":emp_info}, status=200)

    return JsonResponse({"success":False}, status=400)






def getauthempInfo(request):
    if request.method == "GET" and request.is_ajax():
        emp_id=request.GET.get('username')
        emp=User.objects.filter(username=emp_id).first()
        if emp:
            usermaster=user_master.objects.filter(emp_id=emp).first()
            auth_info={
                "name":usermaster.name,
                "designation":usermaster.designation,
                "department":usermaster.department,
                "contactno":usermaster.contactno
            }
            return JsonResponse({"auth_info":auth_info}, status=200)
        else:
            auth_info={
                "name":"No User Found",
                "designation":"",
                "department":"",
                "contactno":""
            }
            return JsonResponse({"auth_info":auth_info}, status=200)
    return JsonResponse({"success":False}, status=400)






@login_required
@role_required(allowed_roles=["Superuser"])
def delete_user(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolestring=usermaster.role
    rolelist=roleslist(request,rolestring)
    nav=dynamicnavbar(request,rolelist)
    users=User.objects.all()
    if not users:
        messages.success(request, 'No User Exist!')
    elif request.method == "POST":
        deleteuser=request.POST.get('emp_id')
        delete=User.objects.filter(username=deleteuser).first()
        if not delete:
            messages.error(request,"Error, No user selected!")
            return redirect('delete_user')
        usermasterupdate=user_master.objects.filter(emp_id=delete.username).first()
        usermasterupdate.role=None
        delete.delete()
        usermasterupdate.save()
        messages.success(request, 'Successfully Deleted!')
        return redirect('delete_user')

    # else:
    #     messages.error(request, 'Error No User selected!')

    context={
        'users':users,
        'nav':nav,
        'usermaster':usermaster,
        'ip':get_client_ip(request),
    }
    return render(request,'delete_user.html',context)




@login_required
@role_required(allowed_roles=["Superuser"])
def forget_password(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolestring=usermaster.role
    rolelist=roleslist(request,rolestring)
    nav=dynamicnavbar(request,rolelist)
    if request.method == "POST":
        emp=request.POST.get('emp_id')
        forgetuser=User.objects.filter(username=emp).first()
        password=request.POST.get('password')
        conpassword=request.POST.get('conpassword')
        if forgetuser and password==conpassword:
            forgetuser.set_password(password)
            forgetuser.save()
            messages.info(request, 'Successfully Changed Password!')
            return redirect('forget_password')
        else:
            messages.info(request, 'Error, Try Again!')
            return redirect('forget_password')
    context={
        'nav':nav,
        'usermaster':usermaster,
        'ip':get_client_ip(request),
    }
    return render(request,'forget_password.html',context)





def forget_path(request):
    if request.method == "POST":
        option=request.POST.get('forget')
        if option=="Email":
            return redirect('password_reset')
        else:
            return redirect('forget_password_path')
    return render(request,'forget_password_path.html',{})




class ChartData(APIView):
    authentication_classes = []
    permission_classes = []
    def get(self,request):
        obj= testc.objects.all()
        serializer=testSerializer(obj,many=True)
        return Response(serializer.data)
