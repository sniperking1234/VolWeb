from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from yararules.models import YaraRule
from yararules.serializers import YaraRuleSerializer
from yararules.utils import is_batch_upload_active
from volatility_engine.tasks import start_yararule_validation, start_ruleset_validation
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import logging

@receiver(post_save, sender=YaraRule)
def send_yara_rule_created(sender, instance, created, **kwargs):
    if created:
        start_yararule_validation.apply_async(args=[instance.id])
        
        # Check if we're in batch upload mode
        if is_batch_upload_active():
            return
    
    # Send WebSocket notification only if NOT in batch upload
    channel_layer = get_channel_layer()
    serializer = YaraRuleSerializer(instance)
    async_to_sync(channel_layer.group_send)(
        "yararules",  
        {"type": "send_notification", "status": "created" if created else "updated", "message": serializer.data},
    )

@receiver(post_delete, sender=YaraRule)
def send_yara_rule_deleted(sender, instance, **kwargs):
    """
    Signal handler for YaraRule deletion.
    
    - Always sends deletion notification
    - Triggers ruleset validation if the rule was linked to a ruleset
    """    
    channel_layer = get_channel_layer()
    
    # Create a minimal representation for the deleted rule
    # to avoid accessing potentially deleted related objects
    deleted_rule_data = {
        'id': instance.id,
        'name': instance.name,
        'status': instance.status,
        'is_active': instance.is_active,
        'linked_yararuleset': None
    }
    
    async_to_sync(channel_layer.group_send)(
        "yararules", 
        {"type": "send_notification", "status": "deleted", "message": deleted_rule_data},
    )
    
    # If the deleted rule was linked to a ruleset, trigger ruleset re-validation
    try:
        ruleset_id = getattr(instance, 'linked_yararuleset_id', None)
        if ruleset_id and not is_batch_upload_active():
            # Attempt to mark ruleset as needing recompilation and enqueue validation
            try:
                from yararulesets.models import YaraRuleSet
                ruleset = YaraRuleSet.objects.get(id=ruleset_id)
                ruleset.status = 0
                ruleset.save(update_fields=['status'])
                start_ruleset_validation.apply_async(args=[ruleset.id])
            except Exception as e:
                logging.getLogger(__name__).warning(f"Failed to trigger ruleset validation after rule delete: {e}")
    except Exception:
        # Defensive: do not let signal failures propagate
        logging.getLogger(__name__).exception("Unexpected error in send_yara_rule_deleted signal")
    