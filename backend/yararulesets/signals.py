from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from yararulesets.models import YaraRuleSet
from yararulesets.serializers import YaraRuleSetSerializer
from volatility_engine.tasks import start_ruleset_validation
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

@receiver(post_save, sender=YaraRuleSet)
def send_yara_ruleset_created(sender, instance, created, **kwargs):
    if created:
        start_ruleset_validation.apply_async(args=[instance.id])
    
    channel_layer = get_channel_layer()
    serializer = YaraRuleSetSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "yararulesets",
        {
            "type": "send_notification", 
            "status": "created" if created else "updated", 
            "message": serializer.data
        },
    )

@receiver(post_delete, sender=YaraRuleSet)
def send_yara_ruleset_deleted(sender, instance, **kwargs):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "yararulesets",
        {
            "type": "send_notification", 
            "status": "deleted", 
            "message": {"id": instance.id}
        },
    )