from django.apps import AppConfig

class YararulesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'yararules'
    
    def ready(self):
        import yararules.signals