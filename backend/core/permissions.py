from rest_framework.exceptions import PermissionDenied


def get_accessible_cases(user):
    """Return a Case queryset accessible to the user."""
    from cases.models import Case

    if user.is_superuser:
        return Case.objects.all()
    return Case.objects.filter(linked_users=user)


def user_can_access_case(user, case):
    """Return True if the user has access to the given case."""
    if user.is_superuser:
        return True
    return case.linked_users.filter(id=user.id).exists()


def user_can_access_evidence(user, evidence):
    """Return True if the user has access to the evidence (via its case)."""
    return user_can_access_case(user, evidence.linked_case)


def check_case_access(user, case):
    """Raise PermissionDenied if the user cannot access the case."""
    if not user_can_access_case(user, case):
        raise PermissionDenied("You do not have access to this case.")


def check_evidence_access(user, evidence):
    """Raise PermissionDenied if the user cannot access the evidence."""
    if not user_can_access_evidence(user, evidence):
        raise PermissionDenied("You do not have access to this evidence.")
