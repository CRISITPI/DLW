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
from dlw.models import testc,navbar,user_master,roles,shift_history
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
def login_request(request):
    if request.method=='POST':
        u_id = request.POST.get('user_id')
        pwd=request.POST.get('password')
        user = authenticate(username=u_id, password=pwd)
        if user is not None:
            login(request, user)
            currentuser=user_master.objects.filter(emp_id=user).first()
            rolelist=currentuser.role.split(", ")
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









@login_required
@role_required(allowed_roles=["Superuser"])
def homeadmin(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolelist=usermaster.role.split(", ")
    nav=dynamicnavbar(request,rolelist)
    context={
        'nav':nav,
        'usermaster':usermaster,
        'ip':get_client_ip(request),
    }
    return render(request,'homeadmin.html',context)








@login_required
@role_required(allowed_roles=["Bogie","Wheel","Wheelsub1","Wheelsub2","Bogiesub1","Bogiesub2","Wheel_shop_incharge","Bogie_shop_incharge"])
def homeuser(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolelist=usermaster.role.split(", ")
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
    rolelist=usermaster.role.split(", ")
    nav=dynamicnavbar(request,rolelist)
    emp=user_master.objects.filter(role__isnull=True)
    availableroles=roles.objects.all().values('parent').distinct()
    if request.method == "POST":
        emp_id=request.POST.get('emp_id')
        email=request.POST.get('email')
        role=request.POST.get('role')
        sublevelrole=request.POST.getlist('sublevel')
        sublevelrolelist= ", ".join(sublevelrole)
        password="dlw@123"
        if "Superuser" in sublevelrole and emp_id and role and sublevelrole:
            employee=user_master.objects.filter(emp_id=emp_id).first()
            employee.role=sublevelrolelist
            employee.parent=role
            newuser = User.objects.create_user(username=emp_id, password=password,email=email)
            employee.save()
            newuser.is_staff= True
            newuser.is_superuser=True
            newuser.save()
            messages.success(request, 'Successfully Created!')
            return redirect('create')
        elif "Superuser" not in sublevelrole and emp_id and role and sublevelrole:
            employee=user_master.objects.filter(emp_id=emp_id).first()
            employee.role=sublevelrolelist
            employee.parent=role
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





    





@login_required
@role_required(allowed_roles=["Superuser"])
def update_permission(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolelist=usermaster.role.split(", ")
    nav=dynamicnavbar(request,rolelist)
    users=User.objects.all()
    availableroles=roles.objects.all().values('parent').distinct()
    if request.method == "POST":
        updateuser=request.POST.get('emp_id')
        sublevelrole=request.POST.getlist('sublevel')
        role=request.POST.get('role')
        sublevelrolelist= ", ".join(sublevelrole)
        if updateuser and sublevelrole:
            usermasterupdate=user_master.objects.filter(emp_id=updateuser).first()
            usermasterupdate.role=sublevelrolelist
            usermasterupdate.parent=role
            usermasterupdate.save()
            messages.success(request, 'Successfully Updated!')
            return redirect('update_permission')
        else:
            messages.error(request,"Error!")
            return redirect('update_permission')

    context={
        'users':users,
        'nav':nav,
        'usermaster':usermaster,
        'ip':get_client_ip(request),
        'roles':availableroles
    }
    return render(request,'update_permission.html',context)











@login_required
@role_required(allowed_roles=["Wheel_shop_incharge","Bogie_shop_incharge"])
def update_permission_incharge(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolelist=usermaster.role.split(", ")
    parentrole=roles.objects.all().filter(role__in=rolelist).first()
    available=roles.objects.all().filter(parent=parentrole.parent).values('role').exclude(role__in=rolelist)
    users=user_master.objects.all().filter(parent=parentrole.parent).values('emp_id').exclude(role__in=rolelist)
    nav=dynamicnavbar(request,rolelist)
    if request.method == "POST":
        updateuser=request.POST.get('emp_id')
        sublevelrole=request.POST.getlist('sublevel')
        sublevelrolelist= ", ".join(sublevelrole)
        if updateuser and sublevelrole:
            usermasterupdate=user_master.objects.filter(emp_id=updateuser).first()
            usermasterupdate.role=sublevelrolelist
            usermasterupdate.save()
            messages.success(request, 'Successfully Updated!')
            return redirect('update_permission_incharge')
        else:
            messages.error(request,"Error!")
            return redirect('update_permission_incharge')

    context={
        'users':users,
        'nav':nav,
        'usermaster':usermaster,
        'ip':get_client_ip(request),
        'roles':available,
    }
    return render(request,'update_permission_incharge.html',context)






# @login_required
# @role_required(allowed_roles=["Wheel_shop_incharge","Bogie_shop_incharge"])
# def update_emp_shift(request):
#     cuser=request.user
#     usermaster=user_master.objects.filter(emp_id=cuser).first()
#     rolelist=usermaster.role.split(", ")
#     parentrole=roles.objects.all().filter(role__in=rolelist).first()
#     users=user_master.objects.all().filter(parent=parentrole.parent).exclude(role__in=rolelist)
#     nav=dynamicnavbar(request,rolelist)
#     total=users.count()+1
#     cnt=0
#     temp="radio"
#     if request.method == "POST":
#         namelist=[]
#         shiftlist={}
#         for j in range(1,total):
#             temp=temp+str(j)
#             namelist.append(temp)
#             temp="radio"
#         for key in request.POST:
#             for temp in namelist:
#                 if key==temp:
#                     shiftlist[key]=request.POST[key]
#         finallist={}
#         for k,v in shiftlist.items():
#             shiftlist1=k.split('radio')
#             finallist[shiftlist1[1]]=v
#         print(finallist)
#         for k,v in finallist.items():
#             print(k)
#             user=users[int(k)-1].emp_id
#             print(user)
#             updateuser=user_master.objects.get(emp_id=user)
#             print(updateuser)
#             if updateuser.shift_id is None:
#                 updateuser.shift_id=v
#                 updateuser.validity_from=date.today()
#                 updateuser.save()
#                 cnt=cnt+1
#             else:
#                 newhistory=shift_history.objects.create()
#                 newhistory.emp_id=updateuser.emp_id
#                 newhistory.shift_id=updateuser.shift_id
#                 newhistory.validity_from=updateuser.validity_from
#                 newhistory.validity_to=date.today()
#                 newhistory.save()
#                 updateuser.shift_id=v
#                 updateuser.validity_from=date.today()
#                 updateuser.save()
#                 cnt=cnt+1
#         if cnt==total-1:
#             messages.success(request, 'Successfully Updated!')
#             return redirect('update_emp_shift')
#     context={
#         'users':users,
#         'nav':nav,
#         'ip':get_client_ip(request),
#     }
#     return render(request,'update_emp_shift.html',context)



@login_required
@role_required(allowed_roles=["Wheel_shop_incharge","Bogie_shop_incharge"])
def update_emp_shift(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolelist=usermaster.role.split(", ")
    parentrole=roles.objects.all().filter(role__in=rolelist).first()
    users=user_master.objects.all().filter(parent=parentrole.parent).exclude(role__in=rolelist)
    nav=dynamicnavbar(request,rolelist)
    print(date.today())
    context={
        'users':users,
        'nav':nav,
        'ip':get_client_ip(request),
    }
    return render(request,'update_emp_shift.html',context)






def shiftsave(request):
    if request.method=="GET" and request.is_ajax():
        shift=request.GET.get('shift')
        emp_id=request.GET.get('emp')
        datetosave=request.GET.get('seldate')
        if emp_id and shift and datetosave:
            updateuser=user_master.objects.get(emp_id=emp_id)
            print(updateuser)
            if updateuser.shift_id is None:
                updateuser.shift_id=shift
                updateuser.validity_from=datetosave
                updateuser.save()
            else:
                newhistory=shift_history.objects.create()
                newhistory.emp_id=updateuser.emp_id
                newhistory.shift_id=updateuser.shift_id
                newhistory.validity_from=updateuser.validity_from
                newhistory.validity_to=datetosave
                newhistory.save()
                updateuser.shift_id=shift
                updateuser.validity_from=datetosave
                updateuser.save()
    data={}
    return JsonResponse(data)






@login_required
@role_required(allowed_roles=["Superuser"])
def update_emp_shift_admin(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolelist=usermaster.role.split(", ")
    nav=dynamicnavbar(request,rolelist)
    parentshops=roles.objects.all().distinct().values('parent').exclude(parent='Superuser')
    if request.method=="POST":
        emp_shiftupdate=request.POST.get('emp_id')
        shift=request.POST.get('shift')
        if emp_shiftupdate and shift:
            updateuser=user_master.objects.get(emp_id=emp_shiftupdate)
            if updateuser.shift_id is None:
                updateuser.shift_id=shift
                updateuser.validity_from=date.today()
                updateuser.save()
                messages.success(request, 'Successfully Updated!')
                return redirect('update_emp_shift_admin')
            else:
                newhistory=shift_history.objects.create()
                newhistory.emp_id=updateuser.emp_id
                newhistory.shift_id=updateuser.shift_id
                newhistory.validity_from=updateuser.validity_from
                newhistory.validity_to=date.today()
                newhistory.save()
                updateuser.shift_id=shift
                updateuser.validity_from=date.today()
                updateuser.save()
                messages.success(request, 'Successfully Updated!')
                return redirect('update_emp_shift_admin')
        else:
            messages.error(request,"Error!")
            return redirect('update_emp_shift_admin')
    context={
        'nav':nav,
        'ip':get_client_ip(request),
        'parentshops':parentshops,
    }
    return render(request,'update_emp_shift_admin.html',context)










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
            "contactno":emp.contactno,
            "currentshift":emp.shift_id
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











def getPermissionInfo(request):
    if request.method == "GET" and request.is_ajax():
        selectrole=request.GET.get('username')
        subshop=roles.objects.filter(parent=selectrole).values('role')
        sub=list(subshop.values('role'))
        permission_info={
            "sub":sub,
        }
        return JsonResponse({"permission_info":permission_info}, status=200)
    return JsonResponse({"success":False}, status=400)










def getshopempinfo(request):
    if request.method == "GET" and request.is_ajax():
        shop=request.GET.get('username')
        usermaster=user_master.objects.filter(parent=shop).values('emp_id')
        print(usermaster)
        neededusers=list(usermaster.values('emp_id'))
        shopemp_info={
            "neededusers":neededusers,
            }
        return JsonResponse({"shopemp_info":shopemp_info}, status=200)
    return JsonResponse({"success":False}, status=400)










@login_required
@role_required(allowed_roles=["Superuser"])
def delete_user(request):
    cuser=request.user
    usermaster=user_master.objects.filter(emp_id=cuser).first()
    rolelist=usermaster.role.split(", ")
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
        if usermasterupdate.shift_id is not None:
            newhistory=shift_history.objects.create()
            newhistory.emp_id=usermasterupdate.emp_id
            newhistory.shift_id=usermasterupdate.shift_id
            newhistory.validity_from=usermasterupdate.validity_from
            newhistory.validity_to=date.today()
            newhistory.save()
            usermasterupdate.role=None
            usermasterupdate.parent=None
            usermasterupdate.shift_id=None
            usermasterupdate.validity_from=None
            delete.delete()
            usermasterupdate.save()
            messages.success(request, 'Successfully Deleted!')
            return redirect('delete_user')
        else:
            usermasterupdate.role=None
            usermasterupdate.parent=None
            usermasterupdate.shift_id=None
            usermasterupdate.validity_from=None
            delete.delete()
            usermasterupdate.save()
            messages.success(request, 'Successfully Deleted!')
            return redirect('delete_user')
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
    rolelist=usermaster.role.split(", ")
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




def test(request):
    employee=user_master.objects.all().filter(parent="Wheel")
    print(employee.count())
    temp="radio"
    if request.method=="POST":
        print(request.POST.get('radio1'))
        print(request.POST.get('radio2'))
        print(employee[0])

    context={
        'employee':employee,
    }
    return render(request,'test.html',context)