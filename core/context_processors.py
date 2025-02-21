from .models import DashboardConfig

def dashboard_config(request):
    config, created = DashboardConfig.objects.get_or_create(id=1)  # Ensure one configuration object exists
    return {'config': config}


