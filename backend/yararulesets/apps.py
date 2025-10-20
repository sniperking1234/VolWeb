from django.apps import AppConfig

class YararulesetsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'yararulesets'
    
    def ready(self):
        import yararulesets.signals