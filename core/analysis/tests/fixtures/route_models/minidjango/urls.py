"""Django urlconf fixture: path / re_path / class view / include."""
from django.urls import include, path, re_path

from minidjango import views

urlpatterns = [
    path("items/<int:pk>/", views.detail),
    re_path(r"^archive/(?P<year>[0-9]{4})/$", views.archive),
    path("cls/", views.ItemView.as_view()),
    path("nested/", include("minidjango.nested_urls")),
]
