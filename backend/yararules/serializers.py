# yararule/serializers.py
from rest_framework import serializers
from .models import YaraRule
from yararulesets.models import YaraRuleSet
import logging

logger = logging.getLogger(__name__)


class YaraRuleListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views — excludes rule_content."""
    ruleset_name = serializers.CharField(source='linked_yararuleset.name', read_only=True, allow_null=True)

    class Meta:
        model = YaraRule
        exclude = ['rule_content']

    def to_representation(self, instance):
        data = super().to_representation(instance)
        try:
            if hasattr(instance, 'linked_yararuleset') and instance.linked_yararuleset:
                data['linked_yararuleset'] = {
                    'id': instance.linked_yararuleset.id,
                    'name': instance.linked_yararuleset.name
                }
            else:
                data['linked_yararuleset'] = None
        except YaraRuleSet.DoesNotExist:
            data['linked_yararuleset'] = None
        return data


class YaraRuleSerializer(serializers.ModelSerializer):
    ruleset_name = serializers.CharField(source='linked_yararuleset.name', read_only=True, allow_null=True)

    class Meta:
        model = YaraRule
        fields = "__all__"
    
    def to_representation(self, instance):
        """
        Override to add linked_yararuleset information safely
        """
        data = super().to_representation(instance)
        
        # Handle the case where linked_yararuleset might not exist anymore (e.g., during cascade delete)
        try:
            if hasattr(instance, 'linked_yararuleset') and instance.linked_yararuleset:
                data['linked_yararuleset'] = {
                    'id': instance.linked_yararuleset.id,
                    'name': instance.linked_yararuleset.name
                }
            else:
                data['linked_yararuleset'] = None
        except YaraRuleSet.DoesNotExist:
            # This can happen during cascade deletes when the ruleset is deleted first
            data['linked_yararuleset'] = None
        
        return data
    
    def create(self, validated_data):
        """
        Create a new YARA rule.
        """
        # Create the rule instance
        rule = super().create(validated_data)
        
        # Trigger validation
        try:
            from volatility_engine.tasks import start_yararule_validation
            start_yararule_validation.delay(rule.id)
        except ImportError:
            logger.warning("Could not import start_yararule_validation task")
        except Exception as e:
            logger.error(f"Error triggering rule validation: {e}")
        
        # Trigger ruleset validation if linked
        if rule.linked_yararuleset:
            try:
                rule.linked_yararuleset.status = 0
                rule.linked_yararuleset.save()
                
                from volatility_engine.tasks import start_ruleset_validation
                start_ruleset_validation.delay(rule.linked_yararuleset.id)
            except ImportError:
                logger.warning("Could not import start_ruleset_validation task")
            except Exception as e:
                logger.error(f"Error triggering ruleset validation: {e}")
        
        return rule
    
    def update(self, instance, validated_data):
        """
        Update a YARA rule.
        """
        # Store old content for comparison
        old_content = instance.rule_content
        old_ruleset = instance.linked_yararuleset
        
        # Update the instance
        rule = super().update(instance, validated_data)
        
        # Check if content changed
        content_changed = 'rule_content' in validated_data and old_content != rule.rule_content
        
        # Check if ruleset changed
        ruleset_changed = 'linked_yararuleset' in validated_data and old_ruleset != rule.linked_yararuleset
        
        # Trigger revalidation if content changed
        if content_changed:
            rule.status = 0
            rule.save(update_fields=['status'])
            
            try:
                from volatility_engine.tasks import start_yararule_validation
                start_yararule_validation.delay(rule.id)
            except ImportError:
                logger.warning("Could not import start_yararule_validation task")
            except Exception as e:
                logger.error(f"Error triggering rule validation: {e}")
        
        # Trigger ruleset revalidation if needed
        if content_changed or ruleset_changed:
            # Revalidate old ruleset if rule was removed from it
            if ruleset_changed and old_ruleset:
                try:
                    old_ruleset.status = 0
                    old_ruleset.save()
                    
                    from volatility_engine.tasks import start_ruleset_validation
                    start_ruleset_validation.delay(old_ruleset.id)
                except ImportError:
                    logger.warning("Could not import start_ruleset_validation task")
                except Exception as e:
                    logger.error(f"Error triggering old ruleset validation: {e}")
            
            # Revalidate new/current ruleset
            if rule.linked_yararuleset:
                try:
                    rule.linked_yararuleset.status = 0
                    rule.linked_yararuleset.save()
                    
                    from volatility_engine.tasks import start_ruleset_validation
                    start_ruleset_validation.delay(rule.linked_yararuleset.id)
                except ImportError:
                    logger.warning("Could not import start_ruleset_validation task")
                except Exception as e:
                    logger.error(f"Error triggering ruleset validation: {e}")
        
        return rule