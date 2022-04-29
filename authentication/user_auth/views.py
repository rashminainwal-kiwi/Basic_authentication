from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages, auth
import constants
from django.contrib.auth import authenticate, login, logout
from django.views import View
#from .forms import RegisterForm, LoginForm
# Create your views here.


def home(request):
    return render(request, 'index.html')


class register(View):
    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        if request.method == 'POST':
            # Get form values
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            username = request.POST['username']
            email = request.POST['email']
            password = request.POST['password']
            password2 = request.POST['password2']

            # Check if Passwords match
            if password == password2:
              # Check username
                if User.objects.filter(username=username).exists():
                    messages.error(
                        request, constants.ERROR['username']['already_taken'])
                    return redirect('register')
                else:
                    if User.objects.filter(email=email).exists():
                        messages.error(
                            request, constants.ERROR['email']['already_exists'])
                        return redirect('register')
                    else:
                        # Looks good
                        user = User.objects.create_user(
                            username=username, password=password, email=email, first_name=first_name, last_name=last_name)
                        # login after register
                        #auth.login(request, user)
                        #messages.success(request,'You are now logged in')
                        # return redirect('index')
                        user.save()
                        messages.success(
                            request, constants.ERROR['register_succesfully']['registered'])
                        return redirect('login')

            else:
                messages.error(
                    request, constants.ERROR['password']['does_not_match'])
                return redirect('register')


class login(View):
    def get(self, request):
        return render(request, "login.html")

    def post(self, request):

        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']

            user = authenticate(username=username, password=password)

            if user is not None:
                auth.login(request, user)
                messages.success(
                    request, constants.ERROR['login_succesfully']['login'])
                return redirect('dashboard')

            else:
                messages.error(
                    request, constants.ERROR['credentials']['Invalid credentials'])
                return redirect('login')

class logout(View):
    def get(self,request): 
        return render(request, 'dashboard.html')
    def post(self,request):
        if request.method == 'POST':
            auth.logout(request)
            messages.success(request, constants.ERROR['logout']['logout'])
        return redirect('home')


def dashboard(request):

    return render(request, 'dashboard.html')
