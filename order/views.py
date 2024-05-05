from django.shortcuts import render, HttpResponse, HttpResponseRedirect,redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from canteen.models import FoodItem
from .models import Cart, Orders, OrderItems,Table
from .forms import LoginRegisterForm,CustomUserCreationForm
import random
from django.utils import timezone
from django.urls import reverse_lazy
from django.contrib.auth.views import PasswordResetView
from django.contrib.messages.views import SuccessMessageMixin
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.contrib.auth.views import PasswordContextMixin
# Create your views here.



def index(request):

    return render(request, 'order/index.html')


class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            {"title": self.title, "subtitle": None, **(self.extra_context or {})}
        )
        return context


class PasswordResetView(PasswordContextMixin, FormView):
    email_template_name = "registration/password_reset_email.html"
    extra_email_context = None
    form_class = PasswordResetForm
    from_email = None
    html_email_template_name = None
    subject_template_name = "registration/password_reset_subject.txt"
    success_url = reverse_lazy("password_reset_done")
    template_name = "registration/password_reset_form.html"
    title = _("Password reset")
    token_generator = default_token_generator

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, form):
        opts = {
            "use_https": self.request.is_secure(),
            "token_generator": self.token_generator,
            "from_email": self.from_email,
            "email_template_name": self.email_template_name,
            "subject_template_name": self.subject_template_name,
            "request": self.request,
            "html_email_template_name": self.html_email_template_name,
            "extra_email_context": self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)


INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"


class PasswordResetDoneView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_reset_done.html"
    title = _("Password reset sent")


class PasswordResetConfirmView(PasswordContextMixin, FormView):
    form_class = SetPasswordForm
    post_reset_login = False
    post_reset_login_backend = None
    reset_url_token = "set-password"
    success_url = reverse_lazy("password_reset_complete")
    template_name = "registration/password_reset_confirm.html"
    title = _("Enter new password")
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        if "uidb64" not in kwargs or "token" not in kwargs:
            raise ImproperlyConfigured(
                "The URL path must contain 'uidb64' and 'token' parameters."
            )

        self.validlink = False
        self.user = self.get_user(kwargs["uidb64"])

        if self.user is not None:
            token = kwargs["token"]
            if token == self.reset_url_token:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(
                        token, self.reset_url_token
                    )
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            ValidationError,
        ):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            auth_login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context["validlink"] = True
        else:
            context.update(
                {
                    "form": None,
                    "title": _("Password reset unsuccessful"),
                    "validlink": False,
                }
            )
        return context


class PasswordResetCompleteView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_reset_complete.html"
    title = _("Password reset complete")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["login_url"] = resolve_url(settings.LOGIN_URL)
        return context


class PasswordChangeView(PasswordContextMixin, FormView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy("password_change_done")
    template_name = "registration/password_change_form.html"
    title = _("Password change")

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        # Updating the password logs out all other sessions for the user
        # except the current one.
        update_session_auth_hash(self.request, form.user)
        return super().form_valid(form)


class PasswordChangeDoneView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_change_done.html"
    title = _("Password change successful")

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)


def explore_foods(request):
    
    food = FoodItem.objects.all()
    name_quantity_of_all_food = []
    if(request.user.is_authenticated):
        cartitems = Cart.objects.filter(username=request.user)
        for f in food:
            find = False
            name_quantity_combo = []
            for item in cartitems:
                if(f.name == item.food.name):
                    name_quantity_combo.append(f.name)
                    name_quantity_combo.append(item.quantity)
                    find = True
                    break
            if(not find):
                name_quantity_combo.append(f.name)
                name_quantity_combo.append('0')
            name_quantity_of_all_food.append(name_quantity_combo)
    return render(request, 'order/items.html', {'food':food, 'cartitems':name_quantity_of_all_food})





def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('pass1')
        password2 = request.POST.get('pass2')
        
        if User.objects.filter(username=username).exists():
            messages.error(request, "This username is already taken")
            return redirect('register')
        
        if password1 != password2:
            messages.warning(request, "Passwords do not match")
            return redirect('register')

        user = User.objects.create_user(username=username, email=email, password=password1)
        user.save()

        if user:
            messages.success(request, "User created successfully")
        else:
            messages.error(request, "User not created successfully")

        return redirect('login')  # Redirect after successful registration or error

    return render(request, 'order/register.html')

    # if(request.method == 'GET'):
    #     form = LoginRegisterForm()
    #     return render(request, 'order/register.html', {'form':form})
    # elif(request.method == 'POST'):
    #     form = LoginRegisterForm(request.POST)
    #     un = request.POST.get('username')
    #     pw = request.POST.get('password')
    #     if(User.objects.filter(username=un).exists()):
    #         messages.warning(request, 'User Already Exists, try other unique username')
    #         return HttpResponseRedirect('/register/')
    #     else:
    #         if(form.is_valid()):
    #             un = form.cleaned_data['username']
    #             pw = form.cleaned_data['password']
    #             new_user = User(username=un)
    #             new_user.set_password(pw)
    #             new_user.save()
    #             messages.success(request, 'Account Created Successfully, You can Login Now')
    #             return HttpResponseRedirect('/login/')

def user_login(request):
    if request.user.is_authenticated:
        return redirect('/')
    if request.method == 'POST':
        username = request.POST['username']
        print(username)
        password = request.POST['password']
        print(password)
        try:
            user = User.objects.get(username=username)
            user = authenticate(request, username=username, password=password) # check password
            print(user)

            if user:
                login(request, user)
                return redirect('index')
        except:
            context = {
                'error_msg':"Username or Password is incorrect"
            }
            return render(request,'order/login.html',context)
    return render(request,'order/login.html')

    # if(request.method == 'GET'):
    #     form = LoginRegisterForm()
    #     return render(request, 'order/login.html', {'form':form})
    # elif(request.method == 'POST'):
    #     form = LoginRegisterForm(request.POST)
    #     un = request.POST.get('username')
    #     pw = request.POST.get('password')
    #     if(not User.objects.filter(username=un).exists()):
    #         messages.warning(request, 'User Does Not Exist or Wrong Password, Try Again')
    #         return HttpResponseRedirect('/login/')
    #     else:
    #         auth_user = authenticate(username=un, password=pw)
    #         if(auth_user):
    #             login(request, auth_user)
    #             return HttpResponseRedirect('/')
    #         else:
    #             messages.warning(request, 'User Does Not Exist or Wrong Password, Try Again')
    #             return HttpResponseRedirect('/login/')

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from .models import FoodItem, Cart

@login_required(login_url='/login/')
def update_cart(request, f_id):
    food = FoodItem.objects.get(id=f_id)
    if Cart.objects.filter(username=request.user, food=food).exists():
        old_quantity = Cart.objects.values_list('quantity', flat=True).get(username=request.user, food=food)
        if request.GET.get('name') == 'increase_cart':
            updated_quantity = old_quantity + 1
            Cart.objects.filter(username=request.user, food=food).update(quantity=updated_quantity)
        elif request.GET.get('name') == 'decrease_cart' and old_quantity > 1:  # Ensure quantity doesn't go below 1
            updated_quantity = old_quantity - 1
            Cart.objects.filter(username=request.user, food=food).update(quantity=updated_quantity)
        elif request.GET.get('name') == 'delete_cart_item':
            item_to_delete = Cart.objects.get(username=request.user, food=food)
            item_to_delete.delete()
    else:
        cart_item = Cart(username=request.user, food=food)
        cart_item.save()

    return HttpResponseRedirect('/cart/')


def about(request):
    return render(request,'order/about.html')



@login_required(login_url='/login/')
def cart(request):
    cartitems = Cart.objects.filter(username=request.user)
    total_amount = 0
    if(cartitems):
        for item in cartitems:
            sub_total = item.food.price * item.quantity
            total_amount += sub_total
    return render(request, 'order/cart.html', {'cartitems':cartitems, 'total_amount':total_amount})

@login_required(login_url='/login/')
def checkout(request):
    if(request.method == 'POST'):
        if(request.POST.get('paymode') == 'Cash'):
            tn_id = 'CASH' + str(random.randint(111111111111111,999999999999999))
            payment_mode = "Cash"
            payment_gateway = "Cash"
        elif(request.POST.get('paymode') == 'Online' and request.POST.get('paygate') == "Paypal"):
            tn_id = request.POST.get('tn_id')
            payment_mode = "Online"
            payment_gateway = "Paypal"
        else:
            return HttpResponse('<H1>Invalid Request</H1>')
        cartitems = Cart.objects.filter(username=request.user)
        total_amount = 0
        new_order = Orders(username=request.user, total_amount=total_amount, payment_mode=payment_mode, transaction_id=tn_id, payment_gateway=payment_gateway)
        new_order.save()
        if(cartitems):
            for item in cartitems:
                OrderItems(username=request.user, order=new_order, name=item.food.name, price=item.food.price, quantity=item.quantity, item_total=item.food.price * item.quantity).save()
                sub_total = item.food.price * item.quantity
                total_amount += sub_total
            Orders.objects.filter(id=new_order.id).update(total_amount=total_amount)
        cartitems.delete()
        return HttpResponseRedirect('/myorders/')
    else:
        return HttpResponse('<H1>Invalid Request</H1>')

@login_required(login_url='/login/')
def my_orders(request):
    orders = Orders.objects.filter(username = request.user).order_by("-order_datetime", "id")
    order_items = OrderItems.objects.filter(username = request.user)
    return render(request, 'order/myorders.html', {'orders':orders, 'order_items':order_items})

@login_required(login_url='/login/')
def seating_plan(request):
    tables = Table.objects.all()
    current_time = timezone.now()
    time_limit = 30
    # Time limit in minute
    for table in tables:
        if not table.is_available and table.booking_time:
            time_difference = current_time - table.booking_time
            if time_difference.total_seconds() / 60>= time_limit:
                table.is_available = True
                table.booked_by = None
                table.booking_time = None
                table.save()

    return render(request, 'order/seating_plan.html', {'tables': tables})

@login_required(login_url='/login/')
def book_table(request, table_number):
    table = Table.objects.get(table_number=table_number)
    if table.is_available:
        table.is_available = False

        table.booked_by = request.user.username
        table.booking_time = timezone.now() 
        # Set the booking time to current time
        table.save()
        message = f"Table {table_number} has been booked for you for 30 minutes!"

    else:
        message = f"Table {table_number}is already booked or busy."
    return render(request, 'order/booking_status.html', {'message': message})



def user_logout(request):
    logout(request)
    messages.success(request, 'Logout Successfully')
    return HttpResponseRedirect('/')