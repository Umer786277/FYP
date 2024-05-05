from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from order.views import PasswordResetView

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('update-cart/<int:f_id>', views.update_cart, name='update-cart'),
    path('cart/', views.cart, name='cart'),
    path('checkout/', views.checkout, name='checkout'),
    path('myorders/', views.my_orders, name='my-orders'),
    path('logout/', views.user_logout, name='logout'),
    path('book-table/<int:table_number>/', views.book_table, name='book_table'),
    path('seating-plan/',views.seating_plan, name='seating_plan'),
    path('about/',views.about,name='about'),
    path('explore_food/',views.explore_foods,name='explore_foods'),

     
    path(
        "password_change/done/",
        views.PasswordChangeDoneView.as_view(),
        name="password_change_done",
    ),
    path("password_reset/", views.PasswordResetView.as_view(), name="password_reset"),
    path(
        "password_reset/done/",
        views.PasswordResetDoneView.as_view(),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        views.PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "reset/done/",
        views.PasswordResetCompleteView.as_view(),
        name="password_reset_complete",
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)