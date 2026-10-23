from django import template

register = template.Library()

@register.filter
def is_readonly_user(user):
    return bool(user.is_authenticated and user.groups.filter(name="Read-only users").exists())
