from django.http import HttpResponse
from django.urls import path


def ok(_request):
    return HttpResponse('ok')


urlpatterns = [
    path('health', ok),
    path('ready', ok),
    path('live', ok),
    path('metrics', ok),
    path('static/app.js', ok),
    path('favicon.ico', ok),
    path('healthcare', ok),
    path('widgets', ok),
]
