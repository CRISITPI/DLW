"""dlw_integrate URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from dlw.views import login_request,logout_request,homeadmin,create,homeuser,ChartData,dynamicnavbar,getEmpInfo,delete_user,forget_password,forget_path,getauthempInfo
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', login_request,name='login'),
    path('logout/',logout_request,name='logout'),
    path('homeadmin/',homeadmin,name='homeadmin'),
    path('createuser/',create,name='create'),
    path('dynamic/',dynamicnavbar),
    path('homeuser/', homeuser, name='homeuser'),
    path('api/chart/data/',ChartData.as_view()),
    path('password_change/done/',auth_views.PasswordChangeView.as_view(template_name='password_reset_inside_complete.html'),name='password_reset_internal_complete'),
    path('password_reset_inside/',auth_views.PasswordChangeView.as_view(template_name='password_reset_inside.html'),name='password_reset_inside'),
    path('password_reset/',auth_views.PasswordResetView.as_view(template_name='password_reset.html'),name='password_reset'),
    path('password_reset/done/',auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'),name='password_reset_done'),
    path('reset/<uidb64>/<token>/',auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'),name='password_reset_confirm'),
    path('reset/done/',auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'),name='password_reset_complete'),
    path('', include('django.contrib.auth.urls')),
    path('ajax/get_emp_info/',getEmpInfo,name='get_emp_info'),
    path('ajax/get_auth_emp_info/',getauthempInfo,name='get_auth_emp_info'),
    path('delete_user/',delete_user,name='delete_user'),
    path('forget_password/', forget_password, name='forget_password'),
    path('forget_password_path/',forget_path,name='forget_password_path'),
]
