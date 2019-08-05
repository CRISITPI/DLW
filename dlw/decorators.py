from django.shortcuts import render,redirect
from django.http import HttpResponse,JsonResponse,HttpResponseRedirect
from django.core.exceptions import PermissionDenied
from dlw.models import user_master





def role_required(allowed_roles=[]):
    def decorator(func):
        def wrap(request,*args,**kwargs):
            cuser=request.user
            usermaster=user_master.objects.get(emp_id=cuser)
            urole=usermaster.role
            if urole in allowed_roles:
                return func(request,*args,**kwargs)
            else:
                raise PermissionDenied
        return wrap
    return decorator



