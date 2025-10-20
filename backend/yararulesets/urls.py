from django.urls import path, include
from rest_framework.routers import DefaultRouter
from yararulesets.views import (
    YaraRuleSetViewSet,
    InitiateUploadView,
    UploadChunkView,
    CompleteUploadView,
    GitHubImportView,
)

router = DefaultRouter()
router.register(r"yararulesets", YaraRuleSetViewSet)

urlpatterns = [
    path(
        "yararulesets/upload/initiate/", InitiateUploadView.as_view(), name="initiate_upload"
    ),
    path("yararulesets/upload/chunk/", UploadChunkView.as_view(), name="upload_chunk"),
    path(
        "yararulesets/upload/complete/", CompleteUploadView.as_view(), name="complete_upload"
    ),
    path('yararulesets/import/github/', GitHubImportView.as_view(), name='yararule-github-import'),
    path("", include(router.urls)),
]